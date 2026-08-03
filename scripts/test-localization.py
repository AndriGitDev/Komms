#!/usr/bin/env python3
"""Negative and behavior tests for the shared localization contract."""

from __future__ import annotations

import copy
import importlib.util
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "localization.py"
SPEC = importlib.util.spec_from_file_location("komms_localization", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
LOCALIZATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LOCALIZATION)
SOURCE_CHECKER_SCRIPT = ROOT / "scripts" / "check-localization-sources.py"
SOURCE_CHECKER_SPEC = importlib.util.spec_from_file_location(
    "komms_localization_source_checker",
    SOURCE_CHECKER_SCRIPT,
)
assert SOURCE_CHECKER_SPEC is not None and SOURCE_CHECKER_SPEC.loader is not None
SOURCE_CHECKER = importlib.util.module_from_spec(SOURCE_CHECKER_SPEC)
SOURCE_CHECKER_SPEC.loader.exec_module(SOURCE_CHECKER)


def catalog(locale: str, messages: dict[str, object]) -> dict[str, object]:
    return {
        "schema": LOCALIZATION.SCHEMA,
        "locale": locale,
        "direction": "ltr",
        "messages": messages,
        "intentionally_unchanged": {},
    }


class LocalizationTests(unittest.TestCase):
    def test_checked_in_catalogs_and_outputs_are_current(self) -> None:
        default, translated = LOCALIZATION.load_pair(require_complete=True)
        LOCALIZATION.check_outputs(
            LOCALIZATION.expected_outputs(default, translated)
        )

    def test_desktop_direct_calls_match_text_and_plural_contracts(self) -> None:
        default, _ = LOCALIZATION.load_pair(require_complete=True)
        messages = default["messages"]
        source = (
            ROOT / "apps" / "desktop" / "ui" / "main.js"
        ).read_text(encoding="utf-8")
        calls = re.compile(
            r'\b(l10n|l10nPlural)\(\s*"([^"]+)"',
            re.DOTALL,
        )
        for match in calls.finditer(source):
            function, message_id = match.groups()
            self.assertIn(message_id, messages)
            value = messages[message_id]
            if function == "l10nPlural":
                self.assertIsInstance(
                    value,
                    dict,
                    f"{message_id} must be a plural message",
                )
            else:
                self.assertIsInstance(
                    value,
                    str,
                    f"{message_id} must be a text message",
                )

    def test_dynamic_ui_literals_are_rejected_at_shell_boundaries(self) -> None:
        cases = (
            (
                SOURCE_CHECKER.JAVASCRIPT_RAW_UI_PATTERN,
                'status.textContent = "Hard-coded status";',
            ),
            (
                SOURCE_CHECKER.KOTLIN_RAW_UI_PATTERN,
                'text = "Hard-coded status"',
            ),
            (
                SOURCE_CHECKER.SWIFT_RAW_DYNAMIC_UI_PATTERN,
                'localError = "Hard-coded status"',
            ),
        )
        for pattern, source in cases:
            with self.subTest(source=source):
                self.assertIsNotNone(pattern.search(source))
        self.assertEqual(SOURCE_CHECKER.unlocalized_dynamic_copy(), {})

    def test_icelandic_layout_expansion_stays_bounded(self) -> None:
        default, translated = LOCALIZATION.load_pair(require_complete=True)
        for message_id, english in default["messages"].items():
            icelandic = translated["messages"][message_id]
            english_forms = (
                english if isinstance(english, dict) else {"text": english}
            )
            icelandic_forms = (
                icelandic if isinstance(icelandic, dict) else {"text": icelandic}
            )
            for form, source_text in english_forms.items():
                translated_text = icelandic_forms[form]
                source_bytes = len(source_text.encode("utf-8"))
                translated_bytes = len(translated_text.encode("utf-8"))
                with self.subTest(message_id=message_id, form=form):
                    self.assertLessEqual(
                        translated_bytes,
                        max(192, source_bytes * 3 + 64),
                        "translation exceeds the bounded layout-expansion budget",
                    )

    def test_missing_translation_fails(self) -> None:
        default = catalog("en-US", {"message": "Message"})
        translated = catalog("is", {"other": "Annað"})
        with self.assertRaisesRegex(LOCALIZATION.CatalogError, "catalog id mismatch"):
            LOCALIZATION.validate_pair(default, translated, require_complete=True)

    def test_placeholder_type_or_position_change_fails(self) -> None:
        default = catalog("en-US", {"count": "%1$d from %2$s"})
        translated = catalog("is", {"count": "%1$s frá %2$s"})
        with self.assertRaisesRegex(LOCALIZATION.CatalogError, "placeholder mismatch"):
            LOCALIZATION.validate_pair(default, translated, require_complete=True)

    def test_plural_kind_or_form_change_fails(self) -> None:
        default = catalog(
            "en-US",
            {"members": {"one": "%1$d member", "other": "%1$d members"}},
        )
        translated = catalog("is", {"members": "%1$d meðlimir"})
        with self.assertRaisesRegex(LOCALIZATION.CatalogError, "text/plural kind"):
            LOCALIZATION.validate_pair(default, translated, require_complete=True)

    def test_bidi_controls_are_rejected_from_catalogs(self) -> None:
        document = catalog("en-US", {"unsafe": "safe\u202eevil"})
        with self.assertRaisesRegex(LOCALIZATION.CatalogError, "bidi controls"):
            LOCALIZATION.validate_catalog_shape(document, Path("catalog.json"))

    def test_non_nfc_text_is_rejected(self) -> None:
        document = catalog("is", {"name": "I\u0301slenska"})
        with self.assertRaisesRegex(LOCALIZATION.CatalogError, "NFC"):
            LOCALIZATION.validate_catalog_shape(document, Path("catalog.json"))

    def test_platform_specific_quote_escape_is_rejected(self) -> None:
        document = catalog("en-US", {"unsafe": "sender\\'s device"})
        with self.assertRaisesRegex(LOCALIZATION.CatalogError, "quote escape"):
            LOCALIZATION.validate_catalog_shape(document, Path("catalog.json"))

    def test_copied_translation_needs_specific_rationale(self) -> None:
        default = catalog("en-US", {"name": "Komms"})
        translated = catalog("is", {"name": "Komms"})
        with self.assertRaisesRegex(LOCALIZATION.CatalogError, "without a rationale"):
            LOCALIZATION.validate_pair(default, translated, require_complete=True)
        translated["intentionally_unchanged"] = {"name": "Registered product name"}
        LOCALIZATION.validate_pair(default, translated, require_complete=True)

    def test_stale_rationale_fails(self) -> None:
        default = catalog("en-US", {"action": "Open"})
        translated = catalog("is", {"action": "Opna"})
        translated["intentionally_unchanged"] = {"action": "not actually unchanged"}
        with self.assertRaisesRegex(LOCALIZATION.CatalogError, "translation differs"):
            LOCALIZATION.validate_pair(default, translated, require_complete=True)

    def test_fallback_uses_english_without_mutating_catalog(self) -> None:
        default = catalog("en-US", {"message": "Message"})
        translated = catalog("is", {"message": "Skilaboð"})
        catalogs = {"en-US": default, "is": translated}
        before = copy.deepcopy(catalogs)
        self.assertEqual(
            LOCALIZATION.resolve_message(catalogs, "fr", "message"),
            "Message",
        )
        self.assertEqual(catalogs, before)

    def test_unknown_id_fails_closed(self) -> None:
        default = catalog("en-US", {"message": "Message"})
        with self.assertRaisesRegex(LOCALIZATION.CatalogError, "unknown"):
            LOCALIZATION.resolve_message({"en-US": default}, "en-US", "missing")

    def test_english_and_icelandic_plural_rules(self) -> None:
        messages = {
            "members": {
                "one": "%1$d member",
                "other": "%1$d members",
            }
        }
        default = catalog("en-US", messages)
        translated = catalog(
            "is",
            {
                "members": {
                    "one": "%1$d meðlimur",
                    "other": "%1$d meðlimir",
                }
            },
        )
        catalogs = {"en-US": default, "is": translated}
        self.assertIn(
            "member",
            LOCALIZATION.resolve_message(
                catalogs,
                "en-US",
                "members",
                count=1,
            ),
        )
        self.assertIn(
            "meðlimur",
            LOCALIZATION.resolve_message(
                catalogs,
                "is",
                "members",
                count=21,
            ),
        )
        self.assertIn(
            "meðlimir",
            LOCALIZATION.resolve_message(
                catalogs,
                "is",
                "members",
                count=11,
            ),
        )

    def test_string_arguments_are_bidi_isolated_and_integers_are_typed(self) -> None:
        rendered = LOCALIZATION.format_message(
            "Added %1$s with %2$d rows",
            ("\u202eexample", 2),
        )
        self.assertEqual(
            rendered,
            f"Added {LOCALIZATION.FSI}\u202eexample{LOCALIZATION.PDI} with 2 rows",
        )
        with self.assertRaisesRegex(LOCALIZATION.CatalogError, "must be an integer"):
            LOCALIZATION.format_message("%1$d", ("2",))

    def test_android_xml_escapes_aapt_quotes_without_corrupting_newlines(self) -> None:
        escaped = LOCALIZATION.xml_text('A friend\'s "code"\\n%1$s')
        self.assertEqual(
            escaped,
            'A friend\\\'s \\"code\\"\\n&#x2068;%1$s&#x2069;',
        )


if __name__ == "__main__":
    unittest.main()
