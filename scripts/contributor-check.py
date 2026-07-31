#!/usr/bin/env python3
"""Run one bounded contributor profile without publication authority."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROFILES_PATH = ROOT / "contributor" / "profiles.json"
SCHEMA = "komms-contributor-profiles/v1"
MAX_PROFILES = 16
MAX_COMMANDS = 8
MAX_ARGUMENTS = 32
FORBIDDEN_EXECUTABLES = {
    "gh",
    "scp",
    "ssh",
    "xcrun",
}
FORBIDDEN_GIT_SUBCOMMANDS = {
    "commit",
    "merge",
    "push",
    "release",
    "tag",
}
FORBIDDEN_CARGO_SUBCOMMANDS = {
    "install",
    "login",
    "owner",
    "publish",
    "search",
    "yank",
}
SENSITIVE_ENV_PREFIXES = (
    "APPLE_",
    "APNS_",
    "AWS_",
    "FCM_",
    "GOOGLE_",
    "KOMMS_ANDROID_KEYSTORE",
    "KOMMS_APNS_",
    "KOMMS_FCM_",
)


class ProfileError(ValueError):
    """The checked-in contributor profile is unsafe or malformed."""


def load_profiles(path: Path = PROFILES_PATH) -> dict[str, dict[str, Any]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProfileError(f"cannot read {path.relative_to(ROOT)}: {error}") from error

    if document.get("schema") != SCHEMA:
        raise ProfileError(f"schema must be {SCHEMA}")
    profiles = document.get("profiles")
    if not isinstance(profiles, dict) or not 1 <= len(profiles) <= MAX_PROFILES:
        raise ProfileError(f"profiles must contain 1–{MAX_PROFILES} entries")

    validated: dict[str, dict[str, Any]] = {}
    for name, profile in profiles.items():
        if not isinstance(name, str) or not name.replace("-", "").isalnum():
            raise ProfileError(f"invalid profile name: {name!r}")
        if not isinstance(profile, dict):
            raise ProfileError(f"{name}: profile must be an object")
        description = profile.get("description")
        paths = profile.get("paths")
        commands = profile.get("commands")
        if not isinstance(description, str) or not description.strip():
            raise ProfileError(f"{name}: description is required")
        if not isinstance(paths, list) or not paths:
            raise ProfileError(f"{name}: at least one owned path is required")
        for relative in paths:
            checked_relative(name, relative)
        if not isinstance(commands, list) or not 1 <= len(commands) <= MAX_COMMANDS:
            raise ProfileError(f"{name}: commands must contain 1–{MAX_COMMANDS} entries")
        for command in commands:
            validate_command(name, command)
        validated[name] = profile
    return validated


def checked_relative(profile: str, value: Any) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ProfileError(f"{profile}: path must be a non-empty string")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ProfileError(f"{profile}: path escapes repository: {value!r}")
    resolved = (ROOT / relative).resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as error:
        raise ProfileError(f"{profile}: path escapes repository: {value!r}") from error
    return resolved


def validate_command(profile: str, command: Any) -> None:
    if not isinstance(command, dict) or set(command) != {"cwd", "argv"}:
        raise ProfileError(f"{profile}: each command needs only cwd and argv")
    checked_relative(profile, command["cwd"])
    argv = command["argv"]
    if not isinstance(argv, list) or not 1 <= len(argv) <= MAX_ARGUMENTS:
        raise ProfileError(f"{profile}: argv must contain 1–{MAX_ARGUMENTS} strings")
    if not all(isinstance(argument, str) and argument for argument in argv):
        raise ProfileError(f"{profile}: argv contains an invalid argument")

    executable = argv[0]
    if executable in FORBIDDEN_EXECUTABLES:
        raise ProfileError(f"{profile}: {executable} is not allowed in contributor checks")
    if executable == "git" and len(argv) > 1 and argv[1] in FORBIDDEN_GIT_SUBCOMMANDS:
        raise ProfileError(f"{profile}: git {argv[1]} changes project history")
    if executable == "cargo" and len(argv) > 1 and argv[1] in FORBIDDEN_CARGO_SUBCOMMANDS:
        raise ProfileError(f"{profile}: cargo {argv[1]} changes an external registry")


def clean_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(SENSITIVE_ENV_PREFIXES)
    }


def display_command(command: dict[str, Any]) -> str:
    cwd = command["cwd"]
    argv = " ".join(json.dumps(argument) for argument in command["argv"])
    return f"(cd {json.dumps(cwd)} && {argv})"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run one checked-in, non-publishing contributor profile. "
            "This is intentionally smaller than the release matrix."
        )
    )
    parser.add_argument("profile", nargs="?", help="profile name")
    parser.add_argument(
        "--list",
        action="store_true",
        help="list available profiles and exit",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and print commands without running them",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(argv or sys.argv[1:])
    try:
        profiles = load_profiles()
    except ProfileError as error:
        print(f"contributor profile error: {error}", file=sys.stderr)
        return 2

    if arguments.list:
        for name in sorted(profiles):
            print(f"{name}: {profiles[name]['description']}")
        return 0
    if not arguments.profile:
        print("choose one profile; use --list to see names", file=sys.stderr)
        return 2
    if arguments.profile not in profiles:
        print(f"unknown contributor profile: {arguments.profile}", file=sys.stderr)
        return 2

    profile = profiles[arguments.profile]
    print(f"Contributor profile: {arguments.profile}")
    print(profile["description"])
    print("Owned paths:")
    for path in profile["paths"]:
        print(f"  - {path}")
    sys.stdout.flush()

    environment = clean_environment()
    for index, command in enumerate(profile["commands"], start=1):
        print(f"[{index}/{len(profile['commands'])}] {display_command(command)}")
        if arguments.dry_run:
            continue
        try:
            subprocess.run(
                command["argv"],
                cwd=ROOT / command["cwd"],
                env=environment,
                check=True,
            )
        except FileNotFoundError:
            print(
                f"missing prerequisite: {command['argv'][0]}; "
                "see docs/44-contributor-path.md",
                file=sys.stderr,
            )
            return 127
        except subprocess.CalledProcessError as error:
            return error.returncode or 1

    suffix = "validated" if arguments.dry_run else "passed"
    print(
        f"Contributor profile {arguments.profile} {suffix}. "
        "No publication, signing, release, push, or merge action was performed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
