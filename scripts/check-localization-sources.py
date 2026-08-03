#!/usr/bin/env python3
"""Reject unregistered static copy at desktop, Android, and iOS boundaries."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCALIZATION_PATH = ROOT / "scripts" / "localization.py"
SPEC = importlib.util.spec_from_file_location(
    "komms_localization",
    LOCALIZATION_PATH,
)
assert SPEC is not None and SPEC.loader is not None
LOCALIZATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LOCALIZATION)

ALPHABETIC = re.compile(r"[A-Za-zÁÐÉÍÓÚÝÞÆÖáðéíóúýþæö]")
STATIC_ATTRIBUTES = frozenset({"aria-label", "placeholder", "title"})
SWIFT_PATTERNS = (
    re.compile(
        r"\b(?:Text|Button|Label|Section|NavigationLink|Toggle|Picker|"
        r"SecureField|TextField|GroupBox|Menu)\(\s*"
        r'"((?:[^"\\]|\\.)*)"'
    ),
    re.compile(
        r"\.(?:navigationTitle|accessibilityLabel|accessibilityHint|"
        r"confirmationDialog|alert|help)\(\s*"
        r'"((?:[^"\\]|\\.)*)"'
    ),
)
SWIFT_SOURCE_PATTERN = re.compile(
    r'\bL10n\.source\(\s*"((?:[^"\\]|\\.)*)"\s*\)',
    re.DOTALL,
)
KOTLIN_SOURCE_PATTERN = re.compile(
    r'\blocalizedSource\(\s*"((?:[^"\\]|\\.)*)"\s*\)',
    re.DOTALL,
)
JAVASCRIPT_SOURCE_PATTERN = re.compile(
    r'\bl10nSource\(\s*"((?:[^"\\]|\\.)*)"\s*\)',
    re.DOTALL,
)
KOTLIN_RAW_UI_PATTERN = re.compile(
    r"\b(?:text|hint|contentDescription|title|subtitle|message|toast|"
    r"setTitle|setMessage|setText|announce|copyText)\s*(?:=|\()\s*"
    r'"(?P<value>(?:[^"\\]|\\.)*'
    r'[A-Za-zÁÐÉÍÓÚÝÞÆÖáðéíóúýþæö](?:[^"\\]|\\.)*)"'
)
SWIFT_RAW_DYNAMIC_UI_PATTERN = re.compile(
    r"\b(?:error|localError|status|notice|message|title|subtitle|label|hint|"
    r"announcement|carrier|name)\s*=\s*"
    r'"(?P<value>(?:[^"\\]|\\.)*[A-Za-z](?:[^"\\]|\\.)*)"'
)
JAVASCRIPT_RAW_UI_PATTERN = re.compile(
    r"(?:\.(?:textContent|innerText|title|placeholder|ariaLabel)\s*=|"
    r"\b(?:showToast|openModal)\s*\()\s*"
    r'(?P<quote>["\'])(?P<value>[^"\'\n]*[A-Za-z][^"\'\n]*)'
    r"(?P=quote)"
)


def normalized(value: str) -> str:
    return " ".join(value.split())


def has_copy(value: str) -> bool:
    return bool(value and ALPHABETIC.search(value))


class DesktopCopyParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.copy: dict[str, set[str]] = {}

    def record(self, value: str, context: str) -> None:
        value = normalized(value)
        if has_copy(value):
            self.copy.setdefault(value, set()).add(context)

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.stack.append(tag)
        line = self.getpos()[0]
        if any(parent in {"script", "style", "svg"} for parent in self.stack):
            return
        for name, value in attrs:
            if name in STATIC_ATTRIBUTES and value:
                self.record(value, f"apps/desktop/ui/index.html:{line} @{name}")

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        line = self.getpos()[0]
        if any(parent in {"script", "style", "svg"} for parent in self.stack):
            return
        for name, value in attrs:
            if name in STATIC_ATTRIBUTES and value:
                self.record(value, f"apps/desktop/ui/index.html:{line} @{name}")

    def handle_endtag(self, tag: str) -> None:
        if tag not in self.stack:
            return
        reverse_index = self.stack[::-1].index(tag)
        self.stack = self.stack[: len(self.stack) - reverse_index - 1]

    def handle_data(self, data: str) -> None:
        if (
            self.stack
            and not any(
                parent in {"script", "style", "svg"} for parent in self.stack
            )
        ):
            self.record(
                data,
                f"apps/desktop/ui/index.html:{self.getpos()[0]} "
                f"<{self.stack[-1]}>",
            )


def desktop_copy() -> dict[str, set[str]]:
    parser = DesktopCopyParser()
    parser.feed(
        (ROOT / "apps" / "desktop" / "ui" / "index.html").read_text(
            encoding="utf-8"
        )
    )
    return parser.copy


def decode_string_literal(raw: str, language: str) -> str:
    try:
        return json.loads(f'"{raw}"')
    except json.JSONDecodeError as error:
        raise ValueError(
            f"cannot decode {language} string {raw!r}: {error}"
        ) from error


def desktop_javascript_copy() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    directory = ROOT / "apps" / "desktop" / "ui"
    for path in sorted(directory.glob("*.js")):
        if path.name == "locales.generated.js":
            continue
        source = path.read_text(encoding="utf-8")
        for match in JAVASCRIPT_SOURCE_PATTERN.finditer(source):
            value = normalized(
                decode_string_literal(match.group(1), "JavaScript")
            )
            if not has_copy(value):
                continue
            line = source.count("\n", 0, match.start()) + 1
            relative = path.relative_to(ROOT).as_posix()
            found.setdefault(value, set()).add(f"{relative}:{line}")
    return found


def android_copy() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    directory = (
        ROOT / "apps" / "android" / "app" / "src" / "main" / "kotlin"
    )
    for path in sorted(directory.rglob("*.kt")):
        source = path.read_text(encoding="utf-8")
        for match in KOTLIN_SOURCE_PATTERN.finditer(source):
            value = normalized(
                decode_string_literal(match.group(1), "Kotlin")
            )
            if not has_copy(value):
                continue
            line = source.count("\n", 0, match.start()) + 1
            relative = path.relative_to(ROOT).as_posix()
            found.setdefault(value, set()).add(f"{relative}:{line}")
    return found


def ios_copy() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    directory = ROOT / "apps" / "ios" / "KommsApp" / "Sources"
    for path in sorted(directory.glob("*.swift")):
        source = path.read_text(encoding="utf-8")
        for pattern in (*SWIFT_PATTERNS, SWIFT_SOURCE_PATTERN):
            for match in pattern.finditer(source):
                raw = match.group(1)
                if r"\(" in raw:
                    continue
                value = normalized(decode_string_literal(raw, "Swift"))
                if not has_copy(value):
                    continue
                line = source.count("\n", 0, match.start()) + 1
                relative = path.relative_to(ROOT).as_posix()
                found.setdefault(value, set()).add(f"{relative}:{line}")
    return found


def raw_ui_literals(
    directory: Path,
    glob: str,
    pattern: re.Pattern[str],
) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in sorted(directory.glob(glob)):
        source = path.read_text(encoding="utf-8")
        for match in pattern.finditer(source):
            value = normalized(match.group("value"))
            if not has_copy(value):
                continue
            line = source.count("\n", 0, match.start()) + 1
            relative = path.relative_to(ROOT).as_posix()
            found.setdefault(value, set()).add(f"{relative}:{line}")
    return found


def unlocalized_dynamic_copy() -> dict[str, set[str]]:
    return merge_copy(
        raw_ui_literals(
            ROOT / "apps" / "desktop" / "ui",
            "*.js",
            JAVASCRIPT_RAW_UI_PATTERN,
        ),
        raw_ui_literals(
            ROOT / "apps" / "android" / "app" / "src" / "main" / "kotlin",
            "**/*.kt",
            KOTLIN_RAW_UI_PATTERN,
        ),
        raw_ui_literals(
            ROOT / "apps" / "ios" / "KommsApp" / "Sources",
            "*.swift",
            SWIFT_RAW_DYNAMIC_UI_PATTERN,
        ),
    )


def merge_copy(*groups: dict[str, set[str]]) -> dict[str, set[str]]:
    merged: dict[str, set[str]] = {}
    for group in groups:
        for value, contexts in group.items():
            merged.setdefault(value, set()).update(contexts)
    return merged


def main() -> int:
    try:
        default, translated = LOCALIZATION.load_pair(require_complete=True)
        registered = LOCALIZATION.source_message_ids(default, translated)
    except LOCALIZATION.CatalogError as error:
        print(f"localization source check failed: {error}", file=sys.stderr)
        return 1

    copy = merge_copy(
        desktop_copy(),
        desktop_javascript_copy(),
        android_copy(),
        ios_copy(),
    )
    ignored = default.get("_intentionally_unlocalized", {})
    missing = sorted(set(copy) - set(registered) - set(ignored))
    stale_aliases = sorted(
        set(default.get("_source_aliases", {})) - set(copy)
    )
    stale_ignored = sorted(set(ignored) - set(copy))
    errors: list[str] = []
    for value, contexts in sorted(unlocalized_dynamic_copy().items()):
        errors.append(
            "unlocalized dynamic UI copy "
            f"{value!r}: {', '.join(sorted(contexts)[:4])}"
        )
    for value in missing:
        contexts = ", ".join(sorted(copy[value])[:4])
        errors.append(f"unregistered static copy {value!r}: {contexts}")
    for value in stale_aliases:
        errors.append(f"unused source alias {value!r}")
    for value in stale_ignored:
        errors.append(f"unused unlocalized rationale {value!r}")

    if errors:
        for error in errors:
            print(f"localization source check failed: {error}", file=sys.stderr)
        return 1

    print(
        f"localization source coverage: {len(copy)} static strings, "
        f"{len(registered)} registered source keys, "
        f"{len(ignored)} justified technical literals"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
