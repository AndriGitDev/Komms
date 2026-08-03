#!/usr/bin/env python3
"""Copy only expected native packages into a bounded release staging directory."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path


KINDS = {
    "linux-x86_64": (".AppImage", ".deb", ".rpm"),
    "macos-universal": (".dmg",),
    "windows-x86_64": (".msi", ".exe"),
    "android-play-arm64": (".apk", ".aab"),
    "android-google-free-arm64": (".apk",),
    "ios-arm64": (".ipa",),
}
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,191}$")
MAX_FILES = 16
MAX_BYTES = 8 * 1024 * 1024 * 1024


class StageError(ValueError):
    """A staging source violated the release artifact contract."""


def stage(args: argparse.Namespace) -> None:
    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    if not VERSION_RE.fullmatch(args.version):
        raise StageError("version must be a bounded semantic version")
    if not source.is_dir() or source.is_symlink():
        raise StageError("source must be a real directory")
    if source == output or source in output.parents or output in source.parents:
        raise StageError("source and output must not contain one another")
    output.mkdir(parents=True, exist_ok=True)
    if output.is_symlink() or not output.is_dir():
        raise StageError("output must be a real directory")

    suffixes = KINDS[args.kind]
    matches: list[Path] = []
    total = 0
    for candidate in sorted(source.rglob("*")):
        if candidate.is_symlink():
            raise StageError(f"{candidate}: symlinks are forbidden")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise StageError(f"{candidate}: unsupported filesystem entry")
        if candidate.name.endswith(suffixes):
            matches.append(candidate)
            total += candidate.stat().st_size
            if len(matches) > MAX_FILES or total > MAX_BYTES:
                raise StageError("artifact source exceeds the staging bound")
    if not matches:
        expected = ", ".join(suffixes)
        raise StageError(f"no {args.kind} artifact matched {expected}")

    for source_file in matches:
        original = source_file.name
        if not SAFE_NAME_RE.fullmatch(original):
            raise StageError(f"{source_file}: unsafe artifact name")
        destination_name = f"Komms-{args.version}-{args.kind}-{original}"
        if not SAFE_NAME_RE.fullmatch(destination_name):
            raise StageError(f"{source_file}: staged artifact name exceeds the release bound")
        destination = output / destination_name
        if destination.exists():
            raise StageError(f"{destination.name}: staged artifact already exists")
        temporary = destination.with_name(f".{destination.name}.tmp")
        shutil.copy2(source_file, temporary)
        os.replace(temporary, destination)

    print(f"staged {len(matches)} {args.kind} artifact(s)")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--source", required=True)
    root.add_argument("--output", required=True)
    root.add_argument("--kind", choices=tuple(KINDS), required=True)
    root.add_argument("--version", required=True)
    return root


def main() -> int:
    try:
        stage(parser().parse_args())
        return 0
    except (OSError, StageError) as error:
        print(f"release staging error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
