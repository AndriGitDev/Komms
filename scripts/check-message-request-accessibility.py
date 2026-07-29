#!/usr/bin/env python3
"""Pin the cross-shell message-request consent and accessibility contract."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def require(
    errors: list[str],
    relative: str,
    text: str,
    expected: tuple[str, ...],
) -> None:
    for marker in expected:
        if marker not in text:
            errors.append(f"{relative}: missing {marker!r}")


def main() -> None:
    errors: list[str] = []

    desktop_html_path = "apps/desktop/ui/index.html"
    desktop_js_path = "apps/desktop/ui/main.js"
    desktop_css_path = "apps/desktop/ui/style.css"
    desktop_html = source(desktop_html_path)
    desktop_js = source(desktop_js_path)
    desktop_css = source(desktop_css_path)
    require(
        errors,
        desktop_html_path,
        desktop_html,
        (
            'role="status" aria-live="polite"',
            'role="list" aria-label="Message requests"',
            'role="list" aria-label="Group invitations"',
            "People you have not accepted stay separate from contacts and conversation history.",
        ),
    )
    require(
        errors,
        desktop_js_path,
        desktop_js,
        (
            'card.setAttribute("role", "listitem")',
            'card.setAttribute("aria-labelledby", heading.id)',
            'name.setAttribute("aria-label", "Private contact name")',
            'accept.setAttribute("aria-label", "Accept message request")',
            'discard.setAttribute("aria-label", "Delete message request")',
            'block.setAttribute("aria-label", "Block message request")',
            'accept.setAttribute("aria-label", "Accept group invitation")',
            'discard.setAttribute("aria-label", "Delete group invitation")',
            "focusFirstRequestControl(root)",
            "cannot delete remote copies",
        ),
    )
    require(
        errors,
        desktop_css_path,
        desktop_css,
        (
            ".request-actions button",
            "min-block-size: 44px",
            "min-inline-size: 44px",
            "@media (prefers-reduced-motion: reduce)",
        ),
    )

    android_path = (
        "apps/android/app/src/main/kotlin/komms/android/MainActivity.kt"
    )
    android_strings_path = "apps/android/app/src/main/res/values/strings.xml"
    android = source(android_path)
    android_strings = source(android_strings_path)
    require(
        errors,
        android_path,
        android,
        (
            "setAccessibilityHeading(true)",
            "labelFor = name.id",
            "orientation = LinearLayout.VERTICAL",
            "session.acceptMessageRequest",
            "session.deleteMessageRequest",
            "session.blockMessageRequest",
            "session.acceptGroupInvitation",
            "session.deleteGroupInvitation",
        ),
    )
    require(
        errors,
        android_strings_path,
        android_strings,
        (
            '<string name="message_request_accept">Accept</string>',
            '<string name="message_request_delete">Delete</string>',
            '<string name="message_request_block">Block</string>',
            "It cannot delete remote copies.",
            "People you have not accepted stay separate from contacts and conversation history.",
        ),
    )

    ios_path = "apps/ios/KommsApp/Sources/MessageRequestsView.swift"
    ios = source(ios_path)
    require(
        errors,
        ios_path,
        ios,
        (
            '.accessibilityElement(children: .combine)',
            ".accessibilityAddTraits(.updatesFrequently)",
            ".accessibilityLabel(",
            "VStack(alignment: .leading, spacing: 8)",
            ".frame(minHeight: 44)",
            'Button("Accept")',
            'Button("Delete", role: .destructive)',
            'Button("Block", role: .destructive)',
            'Button("Join group")',
            "It cannot delete remote copies.",
            "People you have not accepted stay separate from contacts and ",
        ),
    )

    parity_terms = (
        "Message requests",
        "Accept",
        "Delete",
        "Block",
        "Safety number",
    )
    for term in parity_terms:
        if term not in desktop_html + desktop_js:
            errors.append(f"desktop message-request UI: missing parity term {term!r}")
        if term not in android_strings:
            errors.append(f"Android message-request UI: missing parity term {term!r}")
        if term not in ios:
            errors.append(f"iOS message-request UI: missing parity term {term!r}")

    if errors:
        for error in errors:
            print(f"message-request accessibility check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    print(
        "message-request consent, semantics, scalable actions, announcements, "
        "and cross-shell labels are aligned"
    )


if __name__ == "__main__":
    main()
