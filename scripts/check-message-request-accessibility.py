#!/usr/bin/env python3
"""Pin the cross-shell message-request consent and accessibility contract."""

from __future__ import annotations

import json
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
    canonical = json.loads(
        source("locales/en-US.json")
    )["messages"]

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
            'name.setAttribute("aria-label", l10n("message_request_name_hint"))',
            'accept.setAttribute("aria-label", l10n("message_request_accept"))',
            'discard.setAttribute("aria-label", l10n("message_request_delete"))',
            'block.setAttribute("aria-label", l10n("message_request_block"))',
            'accept.setAttribute("aria-label", l10n("group_invitation_accept"))',
            'discard.setAttribute("aria-label", l10n("group_invitation_delete"))',
            "focusFirstRequestControl(root)",
            'l10n("message_request_block_explanation")',
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
            'L10n.text("message_request_block_explanation")',
            'L10n.text("message_requests_intro")',
        ),
    )

    parity_ids = (
        "message_requests_title",
        "message_request_accept",
        "message_request_delete",
        "message_request_block",
        "message_request_safety",
    )
    for message_id in parity_ids:
        if message_id not in canonical:
            errors.append(f"canonical catalog: missing parity id {message_id!r}")
        if (
            f'"{message_id}"' not in desktop_js
            and f'data-l10n="{message_id}"' not in desktop_html
        ):
            errors.append(
                f"desktop message-request UI: missing parity id {message_id!r}"
            )
        if f'name="{message_id}"' not in android_strings:
            errors.append(
                f"Android message-request UI: missing parity id {message_id!r}"
            )
        if (
            f'L10n.text("{message_id}"' not in ios
            and canonical[message_id] not in ios
        ):
            errors.append(
                f"iOS message-request UI: missing parity id {message_id!r}"
            )

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
