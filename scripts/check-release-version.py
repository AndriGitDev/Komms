#!/usr/bin/env python3
"""Fail when a release tag and the application version surfaces disagree."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(f"release version check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def regex_value(path: Path, pattern: str, label: str) -> str:
    match = re.search(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
    if match is None:
        fail(f"could not find {label} in {path.relative_to(ROOT)}")
    return match.group(1)


def main() -> None:
    if len(sys.argv) > 2:
        fail("usage: scripts/check-release-version.py [vMAJOR.MINOR.PATCH]")

    workspace_version = regex_value(
        ROOT / "Cargo.toml",
        r'(?s)^\[workspace\.package\].*?^version\s*=\s*"([^"]+)"',
        "workspace package version",
    )
    if len(sys.argv) == 2:
        tag = sys.argv[1]
        match = re.fullmatch(
            r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag
        )
        if match is None:
            fail(f"tag {tag!r} must have the form vMAJOR.MINOR.PATCH")
        expected = tag[1:]
    else:
        expected = workspace_version
    desktop_crate_version = regex_value(
        ROOT / "apps/desktop/src-tauri/Cargo.toml",
        r'(?s)^\[package\].*?^version\s*=\s*"([^"]+)"',
        "desktop package version",
    )
    with (ROOT / "apps/desktop/src-tauri/tauri.conf.json").open(
        encoding="utf-8"
    ) as source:
        desktop_bundle_version = json.load(source)["version"]

    versions = {
        "Cargo workspace": workspace_version,
        "desktop crate": desktop_crate_version,
        "Tauri bundle": desktop_bundle_version,
        "Android versionName": regex_value(
            ROOT / "apps/android/app/build.gradle.kts",
            r'^\s*versionName\s*=\s*"([^"]+)"',
            "versionName",
        ),
        "iOS CFBundleShortVersionString": regex_value(
            ROOT / "apps/ios/KommsApp/project.yml",
            r'^\s*CFBundleShortVersionString:\s*"([^"]+)"',
            "CFBundleShortVersionString",
        ),
    }

    mismatches = [
        f"{label} is {actual!r}, expected {expected!r}"
        for label, actual in versions.items()
        if actual != expected
    ]
    if mismatches:
        fail("; ".join(mismatches))

    version_code = int(
        regex_value(
            ROOT / "apps/android/app/build.gradle.kts",
            r"^\s*versionCode\s*=\s*([0-9]+)",
            "versionCode",
        )
    )
    if version_code < 1:
        fail("Android versionCode must be positive")

    print(
        f"release version {expected} is aligned across all application surfaces "
        f"(Android versionCode {version_code})"
    )


if __name__ == "__main__":
    main()
