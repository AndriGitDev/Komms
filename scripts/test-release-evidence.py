#!/usr/bin/env python3
"""Regression tests for the bounded release-evidence command."""

from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import sys
import tempfile
import unittest
import tarfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "scripts/release-evidence.py"
ANDROID_LICENSE_COMMAND = ROOT / "scripts/android-license-evidence.py"
REVISION = "1" * 40


def run(*arguments: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        [sys.executable, str(COMMAND), *arguments],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != expected:
        raise AssertionError(
            f"command returned {completed.returncode}, expected {expected}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def write_builder(path: Path, builder_id: str) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": "komms-release-builder/v1",
                "builder_id": builder_id,
                "revision": REVISION,
                "os": "test",
                "architecture": "test",
                "environment": "fresh temporary directory",
                "runner_image": "test-image",
                "isolated": True,
                "tools": [{"name": "test-tool", "version": "1"}],
            }
        ),
        encoding="utf-8",
    )


class ReleaseEvidenceTests(unittest.TestCase):
    def test_dependency_record_embeds_release_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            licenses = root / "android-licenses.json"
            subprocess.run(
                [
                    sys.executable,
                    str(ANDROID_LICENSE_COMMAND),
                    "inventory",
                    "--repository",
                    str(ROOT),
                    "--revision",
                    REVISION,
                    "--output",
                    str(licenses),
                ],
                cwd=ROOT,
                check=True,
            )
            output = root / "dependency-policy.json"
            run(
                "dependency-record",
                "--repository",
                str(ROOT),
                "--revision",
                REVISION,
                "--root-cargo-deny",
                "passed",
                "--desktop-cargo-deny",
                "passed",
                "--android-license-report",
                str(licenses),
                "--android-dependency-locking",
                "passed",
                "--android-dependency-verification",
                "passed",
                "--output",
                str(output),
            )
            record = json.loads(output.read_text(encoding="utf-8"))
            toolchain = record["release_toolchain"]
            self.assertEqual(toolchain["path"], "release/toolchain-v1.json")
            self.assertEqual(
                toolchain["policy"]["schema"],
                "komms-release-toolchain/v1",
            )
            self.assertEqual(
                toolchain["sha256"],
                hashlib.sha256(
                    (ROOT / "release/toolchain-v1.json").read_bytes()
                ).hexdigest(),
            )

    def test_builder_record_is_revision_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "builder.json"
            run(
                "builder-record",
                "--revision",
                REVISION,
                "--builder-id",
                "controlled-linux-1",
                "--os",
                "Linux",
                "--architecture",
                "x86_64",
                "--environment",
                "fresh controlled host",
                "--runner-image",
                "ubuntu-24.04",
                "--isolated",
                "--tool",
                "rustc=1.88.0",
                "--output",
                str(output),
            )
            record = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(record["revision"], REVISION)
            self.assertTrue(record["isolated"])

    def test_bundle_verifies_and_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "input"
            artifacts.mkdir()
            (artifacts / "Komms-0.3.0.test").write_bytes(b"candidate")
            builder = root / "builder.json"
            write_builder(builder, "first")
            bundle = root / "bundle"
            run(
                "bundle",
                "--artifact-dir",
                str(artifacts),
                "--output-dir",
                str(bundle),
                "--revision",
                REVISION,
                "--version",
                "0.3.0",
                "--tag",
                "v0.3.0",
                "--source-date-epoch",
                "1",
                "--builder",
                str(builder),
            )
            verified = run(
                "verify",
                "--bundle-dir",
                str(bundle),
                "--expected-revision",
                REVISION,
            )
            self.assertIn("verified 1 artifacts", verified.stdout)
            (bundle / "artifacts/Komms-0.3.0.test").write_bytes(b"tampered")
            run("verify", "--bundle-dir", str(bundle), expected=2)

    def test_published_artifacts_must_exactly_match_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            published = root / "published"
            published.mkdir()
            candidate = published / "Komms-0.3.0-linux-x86_64.AppImage"
            candidate.write_bytes(b"candidate")
            manifest = root / "artifacts.json"
            run(
                "inventory",
                "--artifact-dir",
                str(published),
                "--revision",
                REVISION,
                "--output",
                str(manifest),
            )
            verified = run(
                "verify-published-artifacts",
                "--artifact-dir",
                str(published),
                "--manifest",
                str(manifest),
                "--expected-revision",
                REVISION,
            )
            self.assertIn("verified 1 published artifacts", verified.stdout)

            (published / "unexpected.txt").write_text("extra", encoding="utf-8")
            run(
                "verify-published-artifacts",
                "--artifact-dir",
                str(published),
                "--manifest",
                str(manifest),
                expected=2,
            )
            (published / "unexpected.txt").unlink()
            candidate.write_bytes(b"changed")
            run(
                "verify-published-artifacts",
                "--artifact-dir",
                str(published),
                "--manifest",
                str(manifest),
                expected=2,
            )

    def test_published_artifacts_reject_manifest_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            published = root / "published"
            published.mkdir()
            (published / "candidate").write_bytes(b"x")
            manifest = root / "artifacts.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "komms-release-artifacts/v1",
                        "revision": REVISION,
                        "artifacts": [
                            {
                                "path": "artifacts/../candidate",
                                "bytes": 1,
                                "mode": "0644",
                                "sha256": hashlib.sha256(b"x").hexdigest(),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            run(
                "verify-published-artifacts",
                "--artifact-dir",
                str(published),
                "--manifest",
                str(manifest),
                expected=2,
            )

    def test_release_asset_preflight_requires_exact_completed_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata = root / "release.json"
            metadata.write_text(
                json.dumps(
                    {
                        "isDraft": True,
                        "assets": [
                            {
                                "name": "Komms-0.3.0-linux-x86_64.AppImage",
                                "size": 9,
                                "digest": "sha256:" + ("1" * 64),
                            },
                            {
                                "name": "Komms-0.3.0-release-evidence.tar.gz",
                                "size": 12,
                                "digest": "sha256:" + ("2" * 64),
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            run(
                "preflight-release-assets",
                "--metadata",
                str(metadata),
                "--version",
                "0.3.0",
            )
            parsed = json.loads(metadata.read_text(encoding="utf-8"))
            parsed["isDraft"] = False
            metadata.write_text(json.dumps(parsed), encoding="utf-8")
            run(
                "preflight-release-assets",
                "--metadata",
                str(metadata),
                "--version",
                "0.3.0",
                expected=2,
            )

    def test_independent_reproduction_requires_durable_separate_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact_digest = hashlib.sha256(b"release").hexdigest()
            manifest = root / "artifacts.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "komms-release-artifacts/v1",
                        "revision": REVISION,
                        "artifacts": [
                            {
                                "path": "artifacts/Komms-0.3.0-linux-x86_64.AppImage",
                                "bytes": 7,
                                "mode": "0644",
                                "sha256": artifact_digest,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            record = root / "reproducibility.json"
            comparison = {
                "schema": "komms-reproducibility-comparison/v1",
                "revision": REVISION,
                "first_builder": {"builder_id": "project-controlled"},
                "second_builder": {"builder_id": "external-controlled"},
                "summary": {
                    "compared": 1,
                    "exact": 1,
                    "normalized": 0,
                    "explained": 0,
                    "unexplained_or_missing": 0,
                },
                "independently_verified": True,
                "independent_evidence": {
                    "separately_administered": True,
                    "administrator": "Named external builder",
                    "environment": "Fresh documented Linux environment",
                    "executed_at": "2026-07-31T00:00:00Z",
                    "report_uri": "https://example.invalid/reproduction/report.json",
                    "report_sha256": "8" * 64,
                },
                "artifacts": [
                    {
                        "path": "artifacts/Komms-0.3.0-linux-x86_64.AppImage",
                        "status": "exact",
                        "sha256": artifact_digest,
                    }
                ],
                "claim": "Separately administered reproduction record.",
            }
            record.write_text(json.dumps(comparison), encoding="utf-8")
            run(
                "validate-reproducibility",
                "--record",
                str(record),
                "--artifact-manifest",
                str(manifest),
                "--expected-revision",
                REVISION,
                "--require-independent",
            )

            comparison.pop("independent_evidence")
            record.write_text(json.dumps(comparison), encoding="utf-8")
            run(
                "validate-reproducibility",
                "--record",
                str(record),
                "--artifact-manifest",
                str(manifest),
                "--expected-revision",
                REVISION,
                "--require-independent",
                expected=2,
            )

    def test_stable_residual_risks_require_revision_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record = Path(temporary) / "risks.json"
            disposition = {
                "schema": "komms-release-residual-risks/v1",
                "profile": "stable-v1",
                "revision": REVISION,
                "decision": "authorized",
                "authorized_by": "Andri",
                "authorized_at": "2026-07-31T00:00:00Z",
                "authorization_evidence": [
                    "revision-bound founder go/no-go record"
                ],
                "risks": [
                    {
                        "id": "known-limit",
                        "status": "accepted",
                        "statement": "Explicitly accepted residual limitation.",
                    }
                ],
            }
            record.write_text(json.dumps(disposition), encoding="utf-8")
            run(
                "validate-residual-risks",
                "--record",
                str(record),
                "--expected-revision",
                REVISION,
                "--require-authorized",
            )
            disposition["risks"][0]["status"] = "open"
            record.write_text(json.dumps(disposition), encoding="utf-8")
            run(
                "validate-residual-risks",
                "--record",
                str(record),
                "--expected-revision",
                REVISION,
                "--require-authorized",
                expected=2,
            )

    def test_zip_comparison_ignores_only_container_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifests: list[Path] = []
            for index, timestamp in enumerate(((2020, 1, 1, 0, 0, 0), (2022, 2, 2, 0, 0, 0))):
                artifacts = root / f"input-{index}"
                artifacts.mkdir()
                archive = artifacts / "Komms-0.3.0.apk"
                with zipfile.ZipFile(archive, "w") as output:
                    info = zipfile.ZipInfo("classes.dex", date_time=timestamp)
                    output.writestr(info, b"same payload")
                builder = root / f"builder-{index}.json"
                write_builder(builder, f"builder-{index}")
                bundle = root / f"bundle-{index}"
                run(
                    "bundle",
                    "--artifact-dir",
                    str(artifacts),
                    "--output-dir",
                    str(bundle),
                    "--revision",
                    REVISION,
                    "--version",
                    "0.3.0",
                    "--tag",
                    "v0.3.0",
                    "--source-date-epoch",
                    "1",
                    "--builder",
                    str(builder),
                )
                manifests.append(bundle / "release-evidence.json")
            report = root / "comparison.json"
            run(
                "compare",
                "--first",
                str(manifests[0]),
                "--second",
                str(manifests[1]),
                "--output",
                str(report),
                "--require",
                "normalized",
            )
            parsed = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(parsed["summary"]["normalized"], 1)
            self.assertEqual(parsed["summary"]["unexplained_or_missing"], 0)

    def test_archive_normalization_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "input"
            artifacts.mkdir()
            archive = artifacts / "Komms-0.3.0-linux-x86_64-package.zip"
            with zipfile.ZipFile(archive, "w") as output:
                info = zipfile.ZipInfo("redirect")
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                output.writestr(info, b"target")
            builder = root / "builder.json"
            write_builder(builder, "unsafe-archive")
            run(
                "bundle",
                "--artifact-dir",
                str(artifacts),
                "--output-dir",
                str(root / "bundle"),
                "--revision",
                REVISION,
                "--version",
                "0.3.0",
                "--tag",
                "v0.3.0",
                "--source-date-epoch",
                "1",
                "--builder",
                str(builder),
                expected=2,
            )

    def test_secret_bearing_builder_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "input"
            artifacts.mkdir()
            (artifacts / "candidate").write_bytes(b"x")
            builder = root / "builder.json"
            builder.write_text(
                json.dumps(
                    {
                        "schema": "komms-release-builder/v1",
                        "builder_id": "bad",
                        "access_token": "must not enter evidence",
                    }
                ),
                encoding="utf-8",
            )
            run(
                "bundle",
                "--artifact-dir",
                str(artifacts),
                "--output-dir",
                str(root / "bundle"),
                "--revision",
                REVISION,
                "--version",
                "0.3.0",
                "--tag",
                "v0.3.0",
                "--source-date-epoch",
                "1",
                "--builder",
                str(builder),
                expected=2,
            )

    def test_checksum_inventory_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "input"
            artifacts.mkdir()
            payload = b"bounded"
            (artifacts / "candidate").write_bytes(payload)
            builder = root / "builder.json"
            write_builder(builder, "exact")
            bundle = root / "bundle"
            run(
                "bundle",
                "--artifact-dir",
                str(artifacts),
                "--output-dir",
                str(bundle),
                "--revision",
                REVISION,
                "--version",
                "0.3.0",
                "--tag",
                "v0.3.0",
                "--source-date-epoch",
                "1",
                "--builder",
                str(builder),
            )
            checksum = hashlib.sha256(payload).hexdigest()
            rows = (bundle / "SHA256SUMS").read_text(encoding="utf-8")
            self.assertIn(f"{checksum}  artifacts/candidate\n", rows)
            (bundle / "unrecorded").write_text("unexpected", encoding="utf-8")
            run("verify", "--bundle-dir", str(bundle), expected=2)

    def test_evidence_archive_is_deterministic_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "input"
            artifacts.mkdir()
            (artifacts / "candidate").write_bytes(b"archive payload")
            builder = root / "builder.json"
            write_builder(builder, "archive")
            bundle = root / "bundle"
            run(
                "bundle",
                "--artifact-dir",
                str(artifacts),
                "--output-dir",
                str(bundle),
                "--revision",
                REVISION,
                "--version",
                "0.3.0",
                "--tag",
                "v0.3.0",
                "--source-date-epoch",
                "123456789",
                "--builder",
                str(builder),
            )
            first = root / "first.tar.gz"
            second = root / "second.tar.gz"
            run("pack", "--bundle-dir", str(bundle), "--output", str(first))
            run("pack", "--bundle-dir", str(bundle), "--output", str(second))
            self.assertEqual(first.read_bytes(), second.read_bytes())

            unpacked = root / "unpacked"
            run("unpack", "--archive", str(first), "--output-dir", str(unpacked))
            run(
                "verify",
                "--bundle-dir",
                str(unpacked / "release-evidence"),
                "--expected-revision",
                REVISION,
            )

    def test_validation_bundle_promotes_to_verified_alpha_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "input"
            artifacts.mkdir()
            candidate = artifacts / "Komms-0.3.0-linux-x86_64-AppImage.AppImage"
            candidate.write_bytes(b"alpha candidate")
            builder = root / "builder.json"
            write_builder(builder, "alpha-builder")
            licenses = root / "android-licenses.json"
            subprocess.run(
                [
                    sys.executable,
                    str(ANDROID_LICENSE_COMMAND),
                    "inventory",
                    "--repository",
                    str(ROOT),
                    "--revision",
                    REVISION,
                    "--output",
                    str(licenses),
                ],
                cwd=ROOT,
                check=True,
            )
            dependency = root / "dependency-policy.json"
            run(
                "dependency-record",
                "--repository",
                str(ROOT),
                "--revision",
                REVISION,
                "--root-cargo-deny",
                "passed",
                "--desktop-cargo-deny",
                "passed",
                "--android-license-report",
                str(licenses),
                "--android-dependency-locking",
                "passed",
                "--android-dependency-verification",
                "passed",
                "--output",
                str(dependency),
            )
            sbom = root / "komms.cdx.json"
            run(
                "sbom",
                "--repository",
                str(ROOT),
                "--revision",
                REVISION,
                "--version",
                "0.3.0",
                "--android-license-report",
                str(licenses),
                "--output",
                str(sbom),
            )
            notes = root / "release-notes.md"
            notes.write_text("Alpha fixture release notes.\n", encoding="utf-8")
            validation = root / "validation"
            run(
                "bundle",
                "--artifact-dir",
                str(artifacts),
                "--output-dir",
                str(validation),
                "--revision",
                REVISION,
                "--version",
                "0.3.0",
                "--tag",
                "v0.3.0",
                "--source-date-epoch",
                "123456789",
                "--builder",
                str(builder),
                "--sbom",
                str(sbom),
                "--android-licenses",
                str(licenses),
                "--dependency-policy",
                str(dependency),
                "--release-notes",
                str(notes),
            )
            artifact_manifest = validation / "artifacts.json"
            artifact_row = json.loads(
                artifact_manifest.read_text(encoding="utf-8")
            )["artifacts"][0]

            signing = root / "signing.json"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/release-signing.py"),
                    "prepare",
                    "--policy",
                    str(ROOT / "release/policy-v1.json"),
                    "--revision",
                    REVISION,
                    "--artifact-manifest",
                    str(artifact_manifest),
                    "--output",
                    str(signing),
                ],
                cwd=ROOT,
                check=True,
            )
            signing_record = json.loads(signing.read_text(encoding="utf-8"))
            manifest_role = signing_record["roles"][0]
            self.assertEqual(manifest_role["id"], "release-manifest")
            manifest_role.update(
                {
                    "status": "verified",
                    "public_fingerprint": "minisign:TEST1234",
                    "verified_at": "2026-07-31T00:00:00Z",
                    "verifier": "bounded-test-verifier",
                    "artifact_sha256": [artifact_row["sha256"]],
                    "evidence": ["detached signature verification passed"],
                    "result": "Exact candidate digest is covered.",
                }
            )
            signing_record["summary"] = {
                "verified": 1,
                "failed": 0,
                "blocked": 0,
                "open": len(signing_record["roles"]) - 1,
            }
            signing.write_text(json.dumps(signing_record), encoding="utf-8")

            qualification = root / "qualification.json"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/release-qualification.py"),
                    "prepare",
                    "--matrix",
                    str(ROOT / "release/qualification-matrix-v1.json"),
                    "--revision",
                    REVISION,
                    "--version",
                    "0.3.0",
                    "--artifact-manifest",
                    str(artifact_manifest),
                    "--output",
                    str(qualification),
                ],
                cwd=ROOT,
                check=True,
            )
            reproducibility = root / "reproducibility.json"
            reproducibility.write_text(
                json.dumps(
                    {
                        "schema": "komms-reproducibility-comparison/v1",
                        "revision": REVISION,
                        "first_builder": {"builder_id": "alpha-builder"},
                        "second_builder": {"builder_id": "controlled-rebuild"},
                        "summary": {
                            "compared": 1,
                            "exact": 1,
                            "normalized": 0,
                            "explained": 0,
                            "unexplained_or_missing": 0,
                        },
                        "independently_verified": False,
                        "artifacts": [
                            {
                                "path": artifact_row["path"],
                                "status": "exact",
                                "sha256": artifact_row["sha256"],
                            }
                        ],
                        "claim": "Controlled exact rebuild only.",
                    }
                ),
                encoding="utf-8",
            )
            residual = root / "residual-risks.json"
            residual.write_text(
                json.dumps(
                    {
                        "schema": "komms-release-residual-risks/v1",
                        "profile": "stable-v1",
                        "decision": "not-authorized",
                        "risks": [
                            {
                                "id": "stable-evidence-open",
                                "status": "open",
                                "statement": "Stable evidence is intentionally open.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            promoted = root / "alpha"
            run(
                "promote",
                "--bundle-dir",
                str(validation),
                "--output-dir",
                str(promoted),
                "--channel",
                "alpha",
                "--policy",
                str(ROOT / "release/policy-v1.json"),
                "--signing",
                str(signing),
                "--qualification",
                str(qualification),
                "--reproducibility",
                str(reproducibility),
                "--residual-risks",
                str(residual),
                "--release-notes",
                str(notes),
            )
            promoted_record = json.loads(
                (promoted / "release-evidence.json").read_text(encoding="utf-8")
            )
            self.assertEqual(promoted_record["channel"], "alpha")
            self.assertFalse(promoted_record["claims"]["production_signed"])
            archive = root / "alpha-release-evidence.tar.gz"
            run(
                "pack",
                "--bundle-dir",
                str(promoted),
                "--output",
                str(archive),
                expected=2,
            )
            (promoted / "SHA256SUMS.sig").write_bytes(b"detached test signature")
            run("pack", "--bundle-dir", str(promoted), "--output", str(archive))
            unpacked = root / "unpacked-alpha"
            run("unpack", "--archive", str(archive), "--output-dir", str(unpacked))
            run(
                "verify",
                "--bundle-dir",
                str(unpacked / "release-evidence"),
                "--expected-revision",
                REVISION,
            )

    def test_unpack_rejects_parent_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "bad.tar.gz"
            payload = root / "payload"
            payload.write_bytes(b"x")
            with tarfile.open(archive, "w:gz") as output:
                output.add(payload, arcname="../outside")
            run(
                "unpack",
                "--archive",
                str(archive),
                "--output-dir",
                str(root / "output"),
                expected=2,
            )
            self.assertFalse((root / "outside").exists())


if __name__ == "__main__":
    unittest.main()
