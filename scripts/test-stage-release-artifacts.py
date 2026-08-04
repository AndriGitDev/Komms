#!/usr/bin/env python3
"""Regression tests for bounded native-package staging."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "scripts/stage-release-artifacts.py"


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


class StageReleaseArtifactTests(unittest.TestCase):
    def test_only_expected_package_types_are_staged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "app-play-release.apk").write_bytes(b"apk")
            (source / "mapping.txt").write_text("private build detail", encoding="utf-8")
            output = root / "output"
            run(
                "--source",
                str(source),
                "--output",
                str(output),
                "--kind",
                "android-play-arm64",
                "--version",
                "0.4.0",
            )
            self.assertEqual(
                [path.name for path in output.iterdir()],
                ["Komms-0.4.0-android-play-arm64-app-play-release.apk"],
            )

    def test_wrong_platform_type_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "Komms.dmg").write_bytes(b"dmg")
            run(
                "--source",
                str(source),
                "--output",
                str(root / "output"),
                "--kind",
                "windows-x86_64",
                "--version",
                "0.4.0",
                expected=2,
            )

    def test_duplicate_destination_is_not_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "Komms.AppImage").write_bytes(b"first")
            output = root / "output"
            arguments = (
                "--source",
                str(source),
                "--output",
                str(output),
                "--kind",
                "linux-x86_64",
                "--version",
                "0.4.0",
            )
            run(*arguments)
            run(*arguments, expected=2)
            self.assertEqual(next(output.iterdir()).read_bytes(), b"first")

    def test_prefixed_release_name_must_remain_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / (("a" * 180) + ".apk")).write_bytes(b"oversized name")
            run(
                "--source",
                str(source),
                "--output",
                str(root / "output"),
                "--kind",
                "android-play-arm64",
                "--version",
                "0.4.0",
                expected=2,
            )


if __name__ == "__main__":
    unittest.main()
