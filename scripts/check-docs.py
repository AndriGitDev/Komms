#!/usr/bin/env python3
"""Validate documentation links, release-control coverage, and public terms."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"!?\[[^\]]*]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
P0_IDS = {f"P0-{number:02d}" for number in range(1, 11)}
CLAIM_RE = re.compile(r"\bSV1-C\d{2}\b")

PUBLIC_COPY = [
    ROOT / "README.md",
    ROOT / "docs/00-start-here.md",
    ROOT / "docs/01-why.md",
    ROOT / "docs/11-feature-scope.md",
    ROOT / "docs/12-feature-delivery-plan.md",
    ROOT / "docs/27-alpha-testing.md",
    ROOT / "docs/28-brand-system.md",
    ROOT / "apps/desktop/README.md",
    ROOT / "apps/android/README.md",
    ROOT / "apps/ios/README.md",
    ROOT / "apps/desktop/ui/index.html",
    ROOT / "apps/desktop/ui/main.js",
    ROOT / "apps/android/app/src/main/res/values/strings.xml",
    ROOT / "apps/ios/KommsApp/Sources/AttachmentView.swift",
]

OVERCLAIM_TERMS = {
    "metadata-free": re.compile(r"\bmetadata-free\b", re.IGNORECASE),
    "truly deletable": re.compile(r"\btruly deletable\b", re.IGNORECASE),
    "works anywhere": re.compile(r"\bworks anywhere\b", re.IGNORECASE),
    "audited control inventory": re.compile(
        r"\baudited (?:controls?|command surface|text editor|modifier)\b",
        re.IGNORECASE,
    ),
}


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def validate_links(errors: list[str]) -> None:
    for markdown in sorted(ROOT.rglob("*.md")):
        if ".git" in markdown.parts or "target" in markdown.parts:
            continue
        source = markdown.read_text(encoding="utf-8")
        for match in LINK_RE.finditer(source):
            target = match.group(1).strip("<>")
            if (
                target.startswith("#")
                or target.startswith("/")
                or "://" in target
                or target.startswith("mailto:")
            ):
                continue
            path_part = unquote(target.split("#", 1)[0].split("?", 1)[0])
            if not path_part:
                continue
            resolved = (markdown.parent / path_part).resolve()
            try:
                resolved.relative_to(ROOT)
            except ValueError:
                errors.append(
                    f"{relative(markdown)}:{line_number(source, match.start())}: "
                    f"relative link escapes the repository: {target}"
                )
                continue
            if not resolved.exists():
                errors.append(
                    f"{relative(markdown)}:{line_number(source, match.start())}: "
                    f"missing relative link target: {target}"
                )


def validate_control_coverage(errors: list[str]) -> None:
    profile_path = ROOT / "docs/30-stable-v1-product-profile.md"
    ledger_path = ROOT / "docs/31-release-evidence-ledger.md"
    profile = profile_path.read_text(encoding="utf-8")
    ledger = ledger_path.read_text(encoding="utf-8")

    ledger_p0 = set(re.findall(r"\bP0-\d{2}\b", ledger))
    if not P0_IDS <= ledger_p0:
        errors.append(
            f"{relative(ledger_path)}: missing P0 gates "
            f"{sorted(P0_IDS - ledger_p0)}"
        )

    profile_claims = set(CLAIM_RE.findall(profile))
    ledger_claims = set(CLAIM_RE.findall(ledger))
    if not profile_claims:
        errors.append(f"{relative(profile_path)}: no stable claim ids found")
    if profile_claims != ledger_claims:
        errors.append(
            "stable claim register mismatch: "
            f"profile-only={sorted(profile_claims - ledger_claims)}, "
            f"ledger-only={sorted(ledger_claims - profile_claims)}"
        )

    slogan = "Private messaging that keeps working."
    for path in (ROOT / "README.md", profile_path):
        if slogan not in path.read_text(encoding="utf-8"):
            errors.append(f"{relative(path)}: required product promise is missing")

    if "**Unassigned**" not in ledger:
        errors.append(
            f"{relative(ledger_path)}: independent roles must remain visibly unassigned"
        )


def validate_terms(errors: list[str]) -> None:
    for path in PUBLIC_COPY:
        source = path.read_text(encoding="utf-8")
        for label, pattern in OVERCLAIM_TERMS.items():
            for match in pattern.finditer(source):
                errors.append(
                    f"{relative(path)}:{line_number(source, match.start())}: "
                    f"public copy uses disallowed term {label!r}"
                )


def main() -> None:
    errors: list[str] = []
    validate_links(errors)
    validate_control_coverage(errors)
    validate_terms(errors)
    if errors:
        for error in errors:
            print(f"documentation check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    print(
        "documentation links, P0/claim coverage, product promise, "
        "and public terminology are valid"
    )


if __name__ == "__main__":
    main()
