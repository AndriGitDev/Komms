#!/usr/bin/env python3
"""Validate and generate the shared Komms localization catalogs."""

from __future__ import annotations

import argparse
import copy
import html
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
LOCALES = ROOT / "locales"
DEFAULT_PATH = LOCALES / "en-US.json"
ICELANDIC_PATH = LOCALES / "is.json"
SHELL_MESSAGES_PATH = LOCALES / "shell-messages.json"
SCHEMA = "komms-localization-catalog/v1"
SHELL_MESSAGES_SCHEMA = "komms-localization-shell-messages/v1"
DEFAULT_LOCALE = "en-US"
SUPPORTED_LOCALES = ("en-US", "is")
MESSAGE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
FORMAT_TOKEN_RE = re.compile(r"%(?:(?P<position>[1-9][0-9]*)\$)?(?P<kind>[sd%])")
ALPHABETIC_RE = re.compile(r"[A-Za-zÁÐÉÍÓÚÝÞÆÖáðéíóúýþæö]")
MAX_MESSAGES = 2_048
MAX_MESSAGE_BYTES = 8_192
MAX_UNCHANGED_REASON_BYTES = 256
PLURAL_FORMS = frozenset({"one", "other"})
DISALLOWED_BIDI = frozenset(
    {
        "\u200e",  # left-to-right mark
        "\u200f",  # right-to-left mark
        "\u202a",  # left-to-right embedding
        "\u202b",  # right-to-left embedding
        "\u202c",  # pop directional formatting
        "\u202d",  # left-to-right override
        "\u202e",  # right-to-left override
        "\u2066",  # left-to-right isolate
        "\u2067",  # right-to-left isolate
        "\u2068",  # first-strong isolate
        "\u2069",  # pop directional isolate
    }
)
FSI = "\u2068"
PDI = "\u2069"

ANDROID_ENGLISH = (
    ROOT / "apps" / "android" / "app" / "src" / "main" / "res"
    / "values" / "strings.xml"
)
ANDROID_ICELANDIC = (
    ROOT / "apps" / "android" / "app" / "src" / "main" / "res"
    / "values-is" / "strings.xml"
)
ANDROID_SOURCE_IDS = (
    ROOT / "apps" / "android" / "app" / "src" / "main" / "res"
    / "raw" / "localization_source_ids.json"
)
DESKTOP_BUNDLE = ROOT / "apps" / "desktop" / "ui" / "locales.generated.js"
IOS_RESOURCES = (
    ROOT / "apps" / "ios" / "KommsApp" / "Resources" / "Localization"
)
IOS_ENGLISH_LPROJ = (
    ROOT / "apps" / "ios" / "KommsApp" / "Resources" / "en.lproj"
    / "InfoPlist.strings"
)
IOS_ICELANDIC_LPROJ = (
    ROOT / "apps" / "ios" / "KommsApp" / "Resources" / "is.lproj"
    / "InfoPlist.strings"
)
IOS_ENGLISH_STRINGS = (
    ROOT / "apps" / "ios" / "KommsApp" / "Resources" / "en.lproj"
    / "Localizable.strings"
)
IOS_ICELANDIC_STRINGS = (
    ROOT / "apps" / "ios" / "KommsApp" / "Resources" / "is.lproj"
    / "Localizable.strings"
)


class CatalogError(ValueError):
    """A catalog or generated artifact violates the localization contract."""


def read_catalog(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CatalogError(f"{relative(path)}: cannot read catalog: {error}") from error
    validate_catalog_shape(document, path)
    return document


def read_shell_messages(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CatalogError(
            f"{relative(path)}: cannot read shell messages: {error}"
        ) from error
    if not isinstance(document, dict):
        raise CatalogError(f"{relative(path)}: shell messages must be an object")
    allowed = {
        "schema",
        "messages",
        "aliases",
        "intentionally_unchanged",
        "intentionally_unlocalized",
    }
    unknown = set(document) - allowed
    if unknown:
        raise CatalogError(
            f"{relative(path)}: unknown top-level fields: {sorted(unknown)}"
        )
    if document.get("schema") != SHELL_MESSAGES_SCHEMA:
        raise CatalogError(
            f"{relative(path)}: schema must be {SHELL_MESSAGES_SCHEMA}"
        )
    messages = document.get("messages")
    if not isinstance(messages, dict) or len(messages) > MAX_MESSAGES:
        raise CatalogError(
            f"{relative(path)}: messages must contain at most {MAX_MESSAGES} entries"
        )
    for message_id, localized in messages.items():
        if not isinstance(message_id, str) or not MESSAGE_ID_RE.fullmatch(message_id):
            raise CatalogError(f"{relative(path)}: invalid message id {message_id!r}")
        if not isinstance(localized, dict) or set(localized) != set(SUPPORTED_LOCALES):
            raise CatalogError(
                f"{relative(path)}: {message_id} must contain exactly "
                f"{SUPPORTED_LOCALES}"
            )
        for locale, message in localized.items():
            validate_message(path, f"{message_id}.{locale}", message)
    aliases = document.get("aliases", {})
    if not isinstance(aliases, dict):
        raise CatalogError(f"{relative(path)}: aliases must be an object")
    for source, message_id in aliases.items():
        validate_source_literal(path, "alias", source)
        if not isinstance(message_id, str) or not MESSAGE_ID_RE.fullmatch(message_id):
            raise CatalogError(
                f"{relative(path)}: alias {source!r} has invalid target {message_id!r}"
            )
    unchanged = document.get("intentionally_unchanged", {})
    if not isinstance(unchanged, dict):
        raise CatalogError(
            f"{relative(path)}: intentionally_unchanged must be an object"
        )
    for message_id, reason in unchanged.items():
        if message_id not in messages:
            raise CatalogError(
                f"{relative(path)}: unchanged id {message_id!r} has no message"
            )
        if (
            not isinstance(reason, str)
            or not reason.strip()
            or len(reason.encode("utf-8")) > MAX_UNCHANGED_REASON_BYTES
        ):
            raise CatalogError(
                f"{relative(path)}: unchanged id {message_id!r} needs a bounded reason"
            )
    intentionally_unlocalized = document.get("intentionally_unlocalized", {})
    if not isinstance(intentionally_unlocalized, dict):
        raise CatalogError(
            f"{relative(path)}: intentionally_unlocalized must be an object"
        )
    for source, reason in intentionally_unlocalized.items():
        validate_source_literal(path, "unlocalized", source)
        if (
            not isinstance(reason, str)
            or not reason.strip()
            or len(reason.encode("utf-8")) > MAX_UNCHANGED_REASON_BYTES
        ):
            raise CatalogError(
                f"{relative(path)}: unlocalized source {source!r} "
                "needs a bounded reason"
            )
    return document


def validate_source_literal(path: Path, kind: str, source: Any) -> None:
    if not isinstance(source, str) or not source.strip():
        raise CatalogError(
            f"{relative(path)}: {kind} source must be non-empty text"
        )
    if len(source.encode("utf-8")) > MAX_MESSAGE_BYTES:
        raise CatalogError(
            f"{relative(path)}: {kind} source exceeds {MAX_MESSAGE_BYTES} bytes"
        )
    if unicodedata.normalize("NFC", source) != source:
        raise CatalogError(f"{relative(path)}: {kind} source is not NFC")
    controls = sorted(
        {f"U+{ord(char):04X}" for char in source if char in DISALLOWED_BIDI}
    )
    if controls:
        raise CatalogError(
            f"{relative(path)}: {kind} source contains bidi controls: "
            f"{', '.join(controls)}"
        )


def relative(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def validate_catalog_shape(document: Any, path: Path) -> None:
    if not isinstance(document, dict):
        raise CatalogError(f"{relative(path)}: catalog must be an object")
    allowed = {
        "schema",
        "locale",
        "direction",
        "messages",
        "intentionally_unchanged",
    }
    unknown = set(document) - allowed
    if unknown:
        raise CatalogError(
            f"{relative(path)}: unknown top-level fields: {sorted(unknown)}"
        )
    if document.get("schema") != SCHEMA:
        raise CatalogError(f"{relative(path)}: schema must be {SCHEMA}")
    locale = document.get("locale")
    if locale not in SUPPORTED_LOCALES:
        raise CatalogError(
            f"{relative(path)}: locale must be one of {SUPPORTED_LOCALES}"
        )
    if document.get("direction") != "ltr":
        raise CatalogError(f"{relative(path)}: stable-v1 locales are ltr")

    messages = document.get("messages")
    if not isinstance(messages, dict) or not 1 <= len(messages) <= MAX_MESSAGES:
        raise CatalogError(
            f"{relative(path)}: messages must contain 1–{MAX_MESSAGES} entries"
        )
    for message_id, message in messages.items():
        if not isinstance(message_id, str) or not MESSAGE_ID_RE.fullmatch(message_id):
            raise CatalogError(f"{relative(path)}: invalid message id {message_id!r}")
        validate_message(path, message_id, message)

    unchanged = document.get("intentionally_unchanged", {})
    if not isinstance(unchanged, dict):
        raise CatalogError(
            f"{relative(path)}: intentionally_unchanged must be an object"
        )
    for message_id, reason in unchanged.items():
        if message_id not in messages:
            raise CatalogError(
                f"{relative(path)}: unchanged id {message_id!r} has no message"
            )
        if (
            not isinstance(reason, str)
            or not reason.strip()
            or len(reason.encode("utf-8")) > MAX_UNCHANGED_REASON_BYTES
        ):
            raise CatalogError(
                f"{relative(path)}: unchanged id {message_id!r} needs a bounded reason"
            )


def validate_message(path: Path, message_id: str, message: Any) -> None:
    if isinstance(message, str):
        validate_text(path, message_id, "other", message)
        return
    if not isinstance(message, dict) or set(message) != PLURAL_FORMS:
        raise CatalogError(
            f"{relative(path)}: {message_id} must be text or one/other plural forms"
        )
    for form in sorted(PLURAL_FORMS):
        validate_text(path, message_id, form, message[form])


def validate_text(path: Path, message_id: str, form: str, text: Any) -> None:
    label = f"{relative(path)}: {message_id}[{form}]"
    if not isinstance(text, str) or not text:
        raise CatalogError(f"{label} must be non-empty text")
    if len(text.encode("utf-8")) > MAX_MESSAGE_BYTES:
        raise CatalogError(f"{label} exceeds {MAX_MESSAGE_BYTES} UTF-8 bytes")
    if unicodedata.normalize("NFC", text) != text:
        raise CatalogError(f"{label} is not NFC-normalized")
    if "\\'" in text:
        raise CatalogError(f"{label} contains a platform-specific quote escape")
    controls = sorted({f"U+{ord(char):04X}" for char in text if char in DISALLOWED_BIDI})
    if controls:
        raise CatalogError(f"{label} contains bidi controls: {', '.join(controls)}")
    for char in text:
        category = unicodedata.category(char)
        if category in {"Cc", "Cf"} and char not in {"\n", "\t"}:
            raise CatalogError(f"{label} contains control U+{ord(char):04X}")
    format_signature(text, label)


def format_signature(text: str, label: str = "message") -> tuple[tuple[int, str], ...]:
    signature: list[tuple[int, str]] = []
    cursor = 0
    implicit_position = 1
    while cursor < len(text):
        marker = text.find("%", cursor)
        if marker < 0:
            break
        match = FORMAT_TOKEN_RE.match(text, marker)
        if match is None:
            raise CatalogError(f"{label} contains malformed format token at byte {marker}")
        kind = match.group("kind")
        if kind != "%":
            explicit = match.group("position")
            position = int(explicit) if explicit is not None else implicit_position
            if explicit is None:
                implicit_position += 1
            signature.append((position, kind))
        cursor = match.end()
    return tuple(sorted(signature))


def forms(message: str | dict[str, str]) -> dict[str, str]:
    if isinstance(message, str):
        return {"other": message}
    return message


def validate_pair(
    default: dict[str, Any],
    translated: dict[str, Any],
    *,
    require_complete: bool,
) -> None:
    if default["locale"] != DEFAULT_LOCALE:
        raise CatalogError(f"default catalog locale must be {DEFAULT_LOCALE}")
    if translated["locale"] != "is":
        raise CatalogError("translated catalog locale must be is")

    default_ids = set(default["messages"])
    translated_ids = set(translated["messages"])
    missing = sorted(default_ids - translated_ids)
    extra = sorted(translated_ids - default_ids)
    if missing or extra:
        raise CatalogError(
            f"catalog id mismatch: missing={missing[:8]} extra={extra[:8]}"
        )

    unchanged = translated.get("intentionally_unchanged", {})
    for message_id in sorted(default_ids):
        source = default["messages"][message_id]
        target = translated["messages"][message_id]
        if isinstance(source, str) != isinstance(target, str):
            raise CatalogError(f"{message_id}: text/plural kind differs by locale")
        source_forms = forms(source)
        target_forms = forms(target)
        if set(source_forms) != set(target_forms):
            raise CatalogError(f"{message_id}: plural forms differ by locale")
        for form in source_forms:
            expected = format_signature(
                source_forms[form],
                f"{message_id}[{form}] source",
            )
            actual = format_signature(
                target_forms[form],
                f"{message_id}[{form}] translation",
            )
            if actual != expected:
                raise CatalogError(
                    f"{message_id}[{form}]: placeholder mismatch "
                    f"{expected!r} != {actual!r}"
                )

        identical = source == target and contains_alphabetic(source)
        if require_complete and identical and message_id not in unchanged:
            raise CatalogError(
                f"{message_id}: Icelandic text equals English without a rationale"
            )
        if message_id in unchanged and not identical:
            raise CatalogError(
                f"{message_id}: unchanged rationale exists but translation differs"
            )


def contains_alphabetic(message: str | dict[str, str]) -> bool:
    return any(
        ALPHABETIC_RE.search(
            FORMAT_TOKEN_RE.sub("", value).replace("\\n", "").replace("\\t", "")
        )
        for value in forms(message).values()
    )


def isolate_android_placeholders(text: str) -> str:
    pieces: list[str] = []
    cursor = 0
    for match in FORMAT_TOKEN_RE.finditer(text):
        pieces.append(text[cursor : match.start()])
        token = match.group(0)
        if match.group("kind") == "s":
            pieces.extend((FSI, token, PDI))
        else:
            pieces.append(token)
        cursor = match.end()
    pieces.append(text[cursor:])
    return "".join(pieces)


def xml_text(text: str) -> str:
    android_escaped = (
        isolate_android_placeholders(text)
        .replace("'", "\\'")
        .replace('"', '\\"')
    )
    escaped = html.escape(android_escaped, quote=False)
    return escaped.replace(FSI, "&#x2068;").replace(PDI, "&#x2069;")


def android_xml(catalog: dict[str, Any]) -> bytes:
    output = [
        '<?xml version="1.0" encoding="utf-8"?>',
        "<resources>",
        "    <!-- Canonical stable identifiers; edit locales/*.json, then regenerate. -->",
    ]
    for message_id, message in catalog["messages"].items():
        if isinstance(message, str):
            output.append(
                f'    <string name="{message_id}">{xml_text(message)}</string>'
            )
            continue
        output.append(f'    <plurals name="{message_id}">')
        for form in ("one", "other"):
            output.append(
                f'        <item quantity="{form}">{xml_text(message[form])}</item>'
            )
        output.append("    </plurals>")
    output.extend(("</resources>", ""))
    return "\n".join(output).encode("utf-8")


def desktop_bundle(catalogs: tuple[dict[str, Any], ...]) -> bytes:
    payload = {
        catalog["locale"]: {
            "direction": catalog["direction"],
            "messages": catalog["messages"],
        }
        for catalog in catalogs
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    source_ids = json.dumps(
        source_message_ids(catalogs[0], catalogs[1]),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    source = (
        "/* Canonical Komms localization bundle. */\n"
        "\"use strict\";\n"
        f"globalThis.KOMMS_LOCALIZATION_CATALOGS = Object.freeze({encoded});\n"
        f"globalThis.KOMMS_LOCALIZATION_SOURCE_IDS = Object.freeze({source_ids});\n"
    )
    return source.encode("utf-8")


def android_source_ids(
    default: dict[str, Any],
    translated: dict[str, Any],
) -> bytes:
    return (
        json.dumps(
            source_message_ids(default, translated),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def ios_catalog(catalog: dict[str, Any]) -> bytes:
    document = {
        "schema": catalog["schema"],
        "locale": catalog["locale"],
        "direction": catalog["direction"],
        "messages": catalog["messages"],
    }
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def apple_strings_value(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


def ios_info_plist_strings(catalog: dict[str, Any]) -> bytes:
    messages = catalog["messages"]
    entries = (
        ("NSCameraUsageDescription", "ios_camera_usage"),
        ("NSLocalNetworkUsageDescription", "ios_local_network_usage"),
        ("NSMicrophoneUsageDescription", "ios_microphone_usage"),
    )
    lines = [
        "/* Localized permission explanations from the canonical catalog. */"
    ]
    for plist_key, message_id in entries:
        value = messages[message_id]
        if not isinstance(value, str):
            raise CatalogError(f"{message_id}: permission copy cannot be plural")
        lines.append(f'"{plist_key}" = "{apple_strings_value(value)}";')
    lines.append("")
    return "\n".join(lines).encode("utf-8")


def source_message_ids(
    default: dict[str, Any],
    translated: dict[str, Any],
) -> dict[str, str]:
    source_ids: dict[str, str] = {}
    translated_by_source: dict[str, str] = {}
    for message_id, source in default["messages"].items():
        target = translated["messages"][message_id]
        if (
            not isinstance(source, str)
            or not isinstance(target, str)
            or format_signature(source)
        ):
            continue
        if source in source_ids and translated_by_source[source] != target:
            raise CatalogError(
                f"{message_id}: duplicate English source has conflicting translations"
            )
        source_ids.setdefault(source, message_id)
        translated_by_source[source] = target
    for source, message_id in default.get("_source_aliases", {}).items():
        target = translated["messages"][message_id]
        if not isinstance(target, str):
            raise CatalogError(f"{message_id}: source alias cannot target a plural")
        if source in source_ids and translated_by_source[source] != target:
            raise CatalogError(
                f"{message_id}: source alias conflicts with a catalog message"
            )
        source_ids[source] = message_id
        translated_by_source[source] = target
    return source_ids


def ios_localizable_strings(
    default: dict[str, Any],
    translated: dict[str, Any],
    locale: str,
) -> bytes:
    source_ids = source_message_ids(default, translated)
    catalog = default if locale == DEFAULT_LOCALE else translated
    lines = [
        "/* Generated source-key adapter; stable ids live in locales/*.json. */"
    ]
    for source, message_id in sorted(source_ids.items()):
        target = catalog["messages"][message_id]
        if not isinstance(target, str):
            raise CatalogError(f"{message_id}: source-key message cannot be plural")
        lines.append(
            f'"{apple_strings_value(source)}" = '
            f'"{apple_strings_value(target)}";'
        )
    lines.append("")
    return "\n".join(lines).encode("utf-8")


def expected_outputs(
    default: dict[str, Any],
    translated: dict[str, Any],
) -> dict[Path, bytes]:
    return {
        ANDROID_ENGLISH: android_xml(default),
        ANDROID_ICELANDIC: android_xml(translated),
        ANDROID_SOURCE_IDS: android_source_ids(default, translated),
        DESKTOP_BUNDLE: desktop_bundle((default, translated)),
        IOS_RESOURCES / "en-US.json": ios_catalog(default),
        IOS_RESOURCES / "is.json": ios_catalog(translated),
        IOS_ENGLISH_LPROJ: ios_info_plist_strings(default),
        IOS_ICELANDIC_LPROJ: ios_info_plist_strings(translated),
        IOS_ENGLISH_STRINGS: ios_localizable_strings(
            default, translated, DEFAULT_LOCALE
        ),
        IOS_ICELANDIC_STRINGS: ios_localizable_strings(
            default, translated, "is"
        ),
    }


def write_outputs(outputs: dict[Path, bytes]) -> None:
    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        print(f"wrote {relative(path)}")


def check_outputs(outputs: dict[Path, bytes]) -> None:
    errors: list[str] = []
    for path, expected in outputs.items():
        try:
            actual = path.read_bytes()
        except OSError as error:
            errors.append(f"{relative(path)}: missing generated artifact: {error}")
            continue
        if actual != expected:
            errors.append(
                f"{relative(path)}: generated artifact is stale; "
                "run python3 scripts/localization.py generate"
            )
    if errors:
        raise CatalogError("\n".join(errors))


def select_plural(locale: str, count: int) -> str:
    if locale == "en-US" and count == 1:
        return "one"
    if locale == "is" and count % 10 == 1 and count % 100 != 11:
        return "one"
    return "other"


def resolve_message(
    catalogs: dict[str, dict[str, Any]],
    locale: str,
    message_id: str,
    *,
    count: int | None = None,
) -> str:
    requested = catalogs.get(locale)
    fallback = catalogs.get(DEFAULT_LOCALE)
    if fallback is None:
        raise CatalogError("default catalog is unavailable")
    message = None if requested is None else requested["messages"].get(message_id)
    if message is None:
        message = fallback["messages"].get(message_id)
    if message is None:
        raise CatalogError(f"unknown localization id: {message_id}")
    if isinstance(message, str):
        if count is not None:
            raise CatalogError(f"{message_id} is not plural")
        return message
    if count is None:
        raise CatalogError(f"{message_id} requires a plural count")
    return message[select_plural(locale if requested is not None else DEFAULT_LOCALE, count)]


def format_message(template: str, arguments: tuple[Any, ...]) -> str:
    values = copy.deepcopy(arguments)

    def replacement(match: re.Match[str]) -> str:
        kind = match.group("kind")
        if kind == "%":
            return "%"
        explicit = match.group("position")
        position = int(explicit) if explicit is not None else replacement.position
        if explicit is None:
            replacement.position += 1
        if position < 1 or position > len(values):
            raise CatalogError(f"missing argument {position}")
        value = values[position - 1]
        if kind == "d":
            if isinstance(value, bool) or not isinstance(value, int):
                raise CatalogError(f"argument {position} must be an integer")
            return str(value)
        rendered = str(value)
        return f"{FSI}{rendered}{PDI}"

    replacement.position = 1  # type: ignore[attr-defined]
    return FORMAT_TOKEN_RE.sub(replacement, template)


def load_pair(require_complete: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    default = read_catalog(DEFAULT_PATH)
    translated = read_catalog(ICELANDIC_PATH)
    if SHELL_MESSAGES_PATH.exists():
        shell_messages = read_shell_messages(SHELL_MESSAGES_PATH)
        default = copy.deepcopy(default)
        translated = copy.deepcopy(translated)
        for message_id, localized in shell_messages["messages"].items():
            if message_id in default["messages"] or message_id in translated["messages"]:
                raise CatalogError(
                    f"{relative(SHELL_MESSAGES_PATH)}: duplicate id {message_id}"
                )
            default["messages"][message_id] = localized[DEFAULT_LOCALE]
            translated["messages"][message_id] = localized["is"]
        unchanged = shell_messages.get("intentionally_unchanged", {})
        overlap = set(unchanged) & set(
            translated.get("intentionally_unchanged", {})
        )
        if overlap:
            raise CatalogError(
                f"{relative(SHELL_MESSAGES_PATH)}: duplicate unchanged rationale "
                f"{sorted(overlap)}"
            )
        translated.setdefault("intentionally_unchanged", {}).update(unchanged)
        aliases = shell_messages.get("aliases", {})
        for source, message_id in aliases.items():
            if message_id not in default["messages"]:
                raise CatalogError(
                    f"{relative(SHELL_MESSAGES_PATH)}: alias {source!r} "
                    f"targets unknown id {message_id}"
                )
            default_message = default["messages"][message_id]
            translated_message = translated["messages"][message_id]
            if (
                not isinstance(default_message, str)
                or not isinstance(translated_message, str)
                or format_signature(default_message)
            ):
                raise CatalogError(
                    f"{relative(SHELL_MESSAGES_PATH)}: alias {source!r} "
                    "must target non-format text"
                )
        default["_source_aliases"] = copy.deepcopy(aliases)
        default["_intentionally_unlocalized"] = copy.deepcopy(
            shell_messages.get("intentionally_unlocalized", {})
        )
    if len(default["messages"]) > MAX_MESSAGES:
        raise CatalogError(f"merged catalogs exceed {MAX_MESSAGES} entries")
    validate_pair(default, translated, require_complete=require_complete)
    return default, translated


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command, help_text in (
        ("validate", "validate catalogs"),
        ("generate", "write platform artifacts"),
        ("check", "validate catalogs and require fresh platform artifacts"),
    ):
        subparser = subparsers.add_parser(command, help=help_text)
        subparser.add_argument(
            "--allow-incomplete",
            action="store_true",
            help="permit untranslated Icelandic entries during local migration only",
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(argv or sys.argv[1:])
    try:
        default, translated = load_pair(
            require_complete=not arguments.allow_incomplete
        )
        outputs = expected_outputs(default, translated)
        if arguments.command == "generate":
            write_outputs(outputs)
        elif arguments.command == "check":
            check_outputs(outputs)
        print(
            f"localization catalogs valid: {len(default['messages'])} stable ids, "
            f"{len(SUPPORTED_LOCALES)} locales"
        )
    except CatalogError as error:
        print(f"localization check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
