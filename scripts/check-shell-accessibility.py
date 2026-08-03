#!/usr/bin/env python3
"""Pin the automated cross-shell accessibility contract and color contrast."""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def require(
    errors: list[str],
    relative: str,
    markers: tuple[str, ...],
) -> None:
    text = source(relative)
    for marker in markers:
        if marker not in text:
            errors.append(f"{relative}: missing {marker!r}")


def rgb(value: str) -> tuple[float, float, float]:
    if not re.fullmatch(r"#[0-9A-Fa-f]{6}", value):
        raise ValueError(f"unsupported color {value!r}")
    return tuple(int(value[index : index + 2], 16) / 255 for index in (1, 3, 5))


def luminance(value: str) -> float:
    channels = []
    for channel in rgb(value):
        channels.append(
            channel / 12.92
            if channel <= 0.04045
            else ((channel + 0.055) / 1.055) ** 2.4
        )
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def contrast(first: str, second: str) -> float:
    lighter, darker = sorted((luminance(first), luminance(second)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def android_colors(relative: str) -> dict[str, str]:
    root = ET.parse(ROOT / relative).getroot()
    return {
        element.attrib["name"]: (element.text or "").strip()
        for element in root.findall("color")
    }


def check_contrast(errors: list[str]) -> None:
    pairs = (
        ("text_primary", "background"),
        ("text_secondary", "background"),
        ("on_accent", "accent"),
        ("danger", "background"),
        ("warning", "background"),
        ("toolbar_on_primary", "toolbar_background"),
    )
    for relative in (
        "apps/android/app/src/main/res/values/colors.xml",
        "apps/android/app/src/main/res/values-night/colors.xml",
    ):
        colors = android_colors(relative)
        for foreground, background in pairs:
            ratio = contrast(colors[foreground], colors[background])
            if ratio < 4.5:
                errors.append(
                    f"{relative}: {foreground}/{background} contrast "
                    f"{ratio:.2f}:1 is below 4.5:1"
                )

    ios = source("apps/ios/KommsApp/Sources/ThemePalette.swift").lower()
    desktop = source("apps/desktop/ui/style.css").lower()
    shared_roles = {
        "background",
        "surface",
        "surface_raised",
        "text_primary",
        "text_secondary",
        "accent",
        "on_accent",
        "danger",
        "warning",
        "ok",
        "brand",
        "deep",
    }
    for relative in (
        "apps/android/app/src/main/res/values/colors.xml",
        "apps/android/app/src/main/res/values-night/colors.xml",
    ):
        for name, value in android_colors(relative).items():
            if name not in shared_roles:
                continue
            if not re.fullmatch(r"#[0-9a-fA-F]{6}", value):
                continue
            digits = value[1:].lower()
            if f"0x{digits}" not in ios and value.lower() not in desktop:
                errors.append(
                    f"{relative}: palette color {value} is absent from both "
                    "desktop and iOS shared roles"
                )


def check_scalable_text(errors: list[str]) -> None:
    android_layouts = ROOT / "apps" / "android" / "app" / "src" / "main" / "res"
    for path in sorted(android_layouts.rglob("*.xml")):
        text = path.read_text(encoding="utf-8")
        if re.search(r'android:textSize="\d+(?:\.\d+)?dp"', text):
            errors.append(
                f"{path.relative_to(ROOT)}: textSize uses dp instead of scalable sp"
            )

    ios_sources = ROOT / "apps" / "ios" / "KommsApp" / "Sources"
    allowed_fixed_symbols = {
        "CustomIconsView.swift": "size * 0.34",
        "ScreenSecurity.swift": ".font(.system(size: 44))",
    }
    for path in sorted(ios_sources.glob("*.swift")):
        text = path.read_text(encoding="utf-8")
        fixed = ".font(.system(size:"
        if fixed in text and allowed_fixed_symbols.get(path.name) not in text:
            errors.append(
                f"{path.relative_to(ROOT)}: fixed point font bypasses Dynamic Type"
            )


def main() -> None:
    errors: list[str] = []

    require(
        errors,
        "apps/desktop/ui/index.html",
        (
            'id="gate-locale" data-l10n-aria-label="language_title"',
            'fieldset class="theme-options" aria-describedby="mode-disclosure"',
            'id="call-status" class="call-status" role="status" aria-live="polite"',
            'id="group-security" class="call-status" role="status" aria-live="polite"',
            'id="messages" role="log" aria-label="Conversation messages"',
            'id="attachment-transfers" aria-label="Attachment transfers"',
            'data-f="request-status" class="sr-status" role="status" aria-live="polite"',
            'id="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"',
            'data-f="error" role="alert"',
        ),
    )
    require(
        errors,
        "apps/desktop/ui/main.js",
        (
            'el.setAttribute("role", isError ? "alert" : "status")',
            'el.setAttribute("aria-atomic", "true")',
            "modalReturnFocus?.focus()",
            'if (e.key !== "Tab") return',
            'event.key === "ArrowDown" || event.key === "ArrowUp"',
            'card.setAttribute("aria-labelledby", heading.id)',
            'progress.setAttribute(',
            'button.setAttribute("aria-pressed", option.selected_by_me',
        ),
    )
    require(
        errors,
        "apps/desktop/ui/style.css",
        (
            "min-block-size: 44px",
            "outline: 3px solid var(--focus)",
            "@media (prefers-contrast: more)",
            "@media (prefers-reduced-motion: reduce)",
            "overflow-wrap: anywhere",
        ),
    )

    require(
        errors,
        "apps/android/app/src/main/res/layout/activity_gate.xml",
        (
            'android:id="@+id/set_language"',
            'android:contentDescription="@string/language_title"',
            'android:minHeight="52dp"',
        ),
    )
    require(
        errors,
        "apps/android/app/src/main/res/layout/activity_chat.xml",
        (
            'android:accessibilityLiveRegion="polite"',
            'android:contentDescription="@string/call_start_description"',
            'android:contentDescription="@string/audio_record_description"',
            'android:layout_width="44dp"',
            'android:layout_height="44dp"',
        ),
    )
    require(
        errors,
        "apps/android/app/src/main/res/layout/activity_settings.xml",
        (
            'android:contentDescription="@string/settings_backup_accessibility"',
            'android:contentDescription="@string/settings_devices_accessibility"',
            'android:id="@+id/set_language"',
            'android:contentDescription="@string/set_mode"',
        ),
    )
    require(
        errors,
        "apps/android/app/src/main/kotlin/komms/android/MainActivity.kt",
        (
            "setAccessibilityHeading(true)",
            "labelFor = name.id",
            "announceForAccessibility",
        ),
    )
    require(
        errors,
        "apps/android/app/src/main/kotlin/komms/android/LocaleController.kt",
        (
            "AppCompatDelegate.setApplicationLocales",
            "LocaleListCompat.getEmptyLocaleList()",
        ),
    )

    require(
        errors,
        "apps/ios/KommsApp/Sources/KommsApp.swift",
        (
            '.accessibilityHidden(screenSecurity.isObscured)',
            '.environment(',
            '@AppStorage("komms.locale")',
        ),
    )
    require(
        errors,
        "apps/ios/KommsApp/Sources/GateView.swift",
        (
            'L10n.text("language_title")',
            '.accessibilityHint(L10n.text("language_note"))',
            ".fixedSize(horizontal: false, vertical: true)",
        ),
    )
    require(
        errors,
        "apps/ios/KommsApp/Sources/MessageRequestsView.swift",
        (
            ".accessibilityElement(children: .combine)",
            ".accessibilityAddTraits(.updatesFrequently)",
            ".frame(minHeight: 44)",
        ),
    )
    require(
        errors,
        "apps/ios/KommsApp/Sources/GroupChatView.swift",
        (
            ".frame(minHeight: 44, maxHeight: 100)",
            '.accessibilityLabel("Group message")',
        ),
    )
    require(
        errors,
        "apps/ios/KommsApp/Sources/AttachmentView.swift",
        (
            ".accessibilityElement()",
            '.accessibilityLabel("Locally derived audio waveform")',
        ),
    )
    require(
        errors,
        "apps/ios/KommsApp/Sources/SettingsView.swift",
        (
            '@AppStorage("komms.locale")',
            'L10n.text("mode_accessibility"',
            'L10n.text("language_title")',
        ),
    )

    check_contrast(errors)
    check_scalable_text(errors)

    if errors:
        for error in errors:
            print(f"shell accessibility check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    print(
        "cross-shell semantics, focus, scalable text, touch targets, "
        "announcements, reduced motion, and AA contrast contracts are aligned"
    )


if __name__ == "__main__":
    main()
