#!/usr/bin/env python3
"""Regression tests for revision-bound release-signing evidence."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "scripts/release-signing.py"
REVISION = "4" * 40
DIGEST = "5" * 64


def run(*arguments: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(COMMAND), *arguments],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != expected:
        raise AssertionError(
            f"returned {result.returncode}, expected {expected}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


class ReleaseSigningTests(unittest.TestCase):
    def prepare(self, root: Path) -> tuple[Path, Path]:
        manifest = root / "artifacts.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema": "komms-release-artifacts/v1",
                    "revision": REVISION,
                    "artifacts": [
                        {
                            "path": (
                                "artifacts/"
                                "Komms-0.3.0-linux-x86_64-test.AppImage"
                            ),
                            "sha256": DIGEST,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        record = root / "signing.json"
        run(
            "prepare",
            "--revision",
            REVISION,
            "--artifact-manifest",
            str(manifest),
            "--output",
            str(record),
        )
        return manifest, record

    def test_validation_channel_accepts_an_open_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, record = self.prepare(Path(temporary))
            result = run(
                "validate",
                "--record",
                str(record),
                "--artifact-manifest",
                str(manifest),
                "--expected-revision",
                REVISION,
                "--channel",
                "validation",
            )
            self.assertIn("verified=0", result.stdout)

    def test_alpha_requires_manifest_signature(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, record = self.prepare(Path(temporary))
            run(
                "validate",
                "--record",
                str(record),
                "--artifact-manifest",
                str(manifest),
                "--channel",
                "alpha",
                expected=2,
            )

    def test_alpha_manifest_role_must_cover_the_exact_artifact_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, record = self.prepare(Path(temporary))
            parsed = json.loads(record.read_text(encoding="utf-8"))
            parsed["roles"][0].update(
                {
                    "status": "verified",
                    "public_fingerprint": "SHA256:release/manifest+test=",
                    "verified_at": "2026-07-31T00:00:00Z",
                    "verifier": "offline fixture verification",
                    "artifact_sha256": [DIGEST],
                    "evidence": ["release-manifest enrollment fixture passed"],
                    "result": "Public identity and exact release artifact set reviewed.",
                }
            )
            parsed["summary"] = {
                "verified": 1,
                "failed": 0,
                "blocked": 0,
                "open": len(parsed["roles"]) - 1,
            }
            record.write_text(json.dumps(parsed), encoding="utf-8")
            run(
                "validate",
                "--record",
                str(record),
                "--artifact-manifest",
                str(manifest),
                "--channel",
                "alpha",
            )

            parsed = json.loads(record.read_text(encoding="utf-8"))
            parsed["roles"][0]["artifact_sha256"] = []
            record.write_text(json.dumps(parsed), encoding="utf-8")
            run(
                "validate",
                "--record",
                str(record),
                "--artifact-manifest",
                str(manifest),
                "--channel",
                "alpha",
                expected=2,
            )

    def test_alpha_requires_the_signing_role_for_an_included_platform(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "artifacts.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "komms-release-artifacts/v1",
                        "revision": REVISION,
                        "artifacts": [
                            {
                                "path": (
                                    "artifacts/"
                                    "Komms-0.3.0-windows-x86_64-test.msi"
                                ),
                                "sha256": DIGEST,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            record = root / "signing.json"
            run(
                "prepare",
                "--revision",
                REVISION,
                "--artifact-manifest",
                str(manifest),
                "--output",
                str(record),
            )
            parsed = json.loads(record.read_text(encoding="utf-8"))
            parsed["roles"][0].update(
                {
                    "status": "verified",
                    "public_fingerprint": "SHA256:release-manifest-test",
                    "verified_at": "2026-07-31T00:00:00Z",
                    "verifier": "offline fixture verification",
                    "artifact_sha256": [DIGEST],
                    "evidence": ["release-manifest fixture passed"],
                    "result": "Exact artifact set reviewed.",
                }
            )
            parsed["summary"] = {
                "verified": 1,
                "failed": 0,
                "blocked": 0,
                "open": len(parsed["roles"]) - 1,
            }
            record.write_text(json.dumps(parsed), encoding="utf-8")
            run(
                "validate",
                "--record",
                str(record),
                "--artifact-manifest",
                str(manifest),
                "--channel",
                "alpha",
                expected=2,
            )

    def test_stable_roles_cover_every_declared_artifact_class_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            specifications = [
                ("windows-x86_64", "msi", "1" * 64),
                ("macos-universal", "dmg", "2" * 64),
                ("linux-x86_64", "AppImage", "3" * 64),
                ("android-play-arm64", "aab", "4" * 64),
                ("android-google-free-arm64", "apk", "6" * 64),
                ("ios-arm64", "ipa", "7" * 64),
            ]
            manifest = root / "artifacts.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "komms-release-artifacts/v1",
                        "revision": REVISION,
                        "artifacts": [
                            {
                                "path": (
                                    f"artifacts/Komms-0.3.0-{artifact_class}-"
                                    f"fixture.{suffix}"
                                ),
                                "sha256": artifact_digest,
                            }
                            for artifact_class, suffix, artifact_digest in specifications
                        ],
                    }
                ),
                encoding="utf-8",
            )
            record = root / "signing.json"
            run(
                "prepare",
                "--revision",
                REVISION,
                "--artifact-manifest",
                str(manifest),
                "--output",
                str(record),
            )
            parsed = json.loads(record.read_text(encoding="utf-8"))
            by_role = {
                "release-manifest": {row[2] for row in specifications},
                "android-play": {"4" * 64},
                "android-google-free": {"6" * 64},
                "apple-ios": {"7" * 64},
                "apple-macos": {"2" * 64},
                "windows-authenticode": {"1" * 64},
            }
            for role in parsed["roles"]:
                identifier = role["id"]
                role.update(
                    {
                        "status": "verified",
                        "public_fingerprint": f"SHA256:{identifier}-fixture",
                        "verified_at": "2026-07-31T00:00:00Z",
                        "verifier": "named platform verifier",
                        "artifact_sha256": sorted(by_role[identifier]),
                        "evidence": ["bounded verifier record"],
                        "result": "Exact artifact class set verified.",
                    }
                )
            parsed["summary"] = {
                "verified": len(parsed["roles"]),
                "failed": 0,
                "blocked": 0,
                "open": 0,
            }
            record.write_text(json.dumps(parsed), encoding="utf-8")
            run(
                "validate",
                "--record",
                str(record),
                "--artifact-manifest",
                str(manifest),
                "--channel",
                "stable",
            )

            parsed["roles"][1]["artifact_sha256"] = ["6" * 64]
            record.write_text(json.dumps(parsed), encoding="utf-8")
            run(
                "validate",
                "--record",
                str(record),
                "--artifact-manifest",
                str(manifest),
                "--channel",
                "stable",
                expected=2,
            )

    def test_secret_bearing_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, record = self.prepare(Path(temporary))
            parsed = json.loads(record.read_text(encoding="utf-8"))
            parsed["roles"][0]["private_key"] = "forbidden"
            record.write_text(json.dumps(parsed), encoding="utf-8")
            run(
                "validate",
                "--record",
                str(record),
                "--artifact-manifest",
                str(manifest),
                "--channel",
                "validation",
                expected=2,
            )


if __name__ == "__main__":
    unittest.main()
